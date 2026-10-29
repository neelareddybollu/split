/* -------------------------------------------------------------------------
 * Split 8 fronthaul scope - one lane per transmitter
 *
 * Draws what a digital oscilloscope draws: a min/max envelope of the raw
 * waveform, in linear amplitude, about a true zero baseline. For each
 * eCPRI packet the smallest and largest I sample are kept and the band
 * between them is filled - the same decimation a scope does per pixel
 * column.
 *
 * ---------------------------------------------------------------------
 * WHAT CHANGED IN THIS REVISION
 *
 * Every earlier version split the capture into exactly two lanes with one
 * question:
 *
 *     int is_dl = (memcmp(bytes + 6, g_dl_mac, 6) == 0);
 *     dir_t *d  = is_dl ? &g_dl : &g_ul;
 *
 * Downlink is "from the gNB", uplink is EVERYTHING ELSE. That is only
 * true while exactly two devices sit on the mirror. Add a third sender of
 * the same frames - a second gNB, a second UE, another test instrument -
 * and its traffic is folded into the uplink accumulator alongside the
 * real uplink. Each device numbers its own packets independently, so two
 * seq_id sequences then interleave in one frame buffer:
 *
 *     device A:  300, 301, 302 ...
 *     device B:    1,   2,   3 ...
 *     as seen:   300,   1, 301,   2, 302,   3 ...
 *
 * It fails two ways, and the quiet one is worse.
 *
 *   Out of phase, every other packet steps backwards, the frame is cut
 *   almost at once, and the lane reports 2 of 640 cells while drop stays
 *   at zero. Loud, obvious, and the lucky case.
 *
 *   In phase - which two frame-synchronised gNBs always are - no packet
 *   ever steps backwards, so the frame-wrap test never trips. The lane
 *   reports a perfect 640/640 while one device silently overwrites the
 *   other cell by cell, and the trace shows the wrong transmitter with
 *   nothing anywhere saying so.
 *
 * So this version stops inferring. The source address alone picks the
 * lane. Senders are discovered as they appear, each keeps its own seq_id
 * state, its own frame assembly, its own envelope, its own alignment and
 * its own drift measurement. Three transmitters show as three traces
 * without being told anything in advance, and nothing can land in anyone
 * else's sequence.
 *
 * Naming is optional and changes no measurement - it fixes a sender's
 * lane position, colour and label so runs are comparable:
 *
 *     ./run.sh sfp1 \
 *         bc:24:11:ec:73:d3=gNB-wnbox4 \
 *         bc:24:11:aa:bb:cc=UE-wnbox7  \
 *         c6:89:58:52:65:2d=FPGA-gNB
 *
 * KEPT FROM gui5
 *
 *   Link geometry is DERIVED from sample rate, numerology and packet size
 *   rather than compiled in, and checked for consistency at start.
 *   Alignment is normalised cross-correlation against a slowly adapted
 *   reference, not peak-finding, so it works with one burst, several, or
 *   a broad waveform, and reports NO LOCK rather than locking onto noise.
 *   Drift in ppm is computed whether or not alignment is applied to the
 *   display. Persistence is a phosphor with a settable afterglow.
 *   Completed frames are published under a per-lane mutex. The Y axis
 *   rises at once and falls slew-limited. A lane that stops transmitting
 *   dims, then blanks. Cursors, per-lane measurements, optional DC mean,
 *   bad/trunc counters.
 *
 * KNOWN LIMITATION, UNCHANGED
 *
 *   The trace is min/max of I only. Q is read for the DC mean and is not
 *   plotted. The true envelope is sqrt(I^2 + Q^2); I alone swings through
 *   zero on every carrier cycle even when the envelope is flat. The
 *   correlation keys on the per-packet span (hi - lo), which brackets the
 *   whole swing and is far less phase-sensitive than I itself.
 *
 *   A lane is a TRANSMITTER, not a direction. With two gNBs on the link
 *   "downlink" is no longer one thing, and this no longer pretends it is.
 * ---------------------------------------------------------------------- */

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <cmath>
#include <cstdint>
#include <thread>
#include <mutex>
#include <chrono>
#include <atomic>

#include <arpa/inet.h>
#include <pcap/pcap.h>

#include <GL/glew.h>
#include <GLFW/glfw3.h>

#include "imgui.h"
#include "implot.h"
#include "backends/imgui_impl_glfw.h"
#include "backends/imgui_impl_opengl3.h"

#define MAX_LANES         6

/* ============================================================== link config */

typedef struct {
    double   rate_hz;
    int      mu;
    int      spp;
    int      bits;
    unsigned ethertype;
    int      seq_base;
    int      hdr_off;
    int      iq_off;
    int      ver;
    int      msgtype;

    int      sps, pps, slots, cells;
    double   cell_us, slot_us, full_scale;
} cfg_t;

static cfg_t C;

static const char *USAGE =
"usage: %s <iface> [mac[=label] ...] [options]\n"
"\n"
"  Every distinct source MAC sending eCPRI gets its own lane, discovered\n"
"  as it appears. Naming a sender is optional and only fixes its lane\n"
"  position, colour and label. Up to %d lanes.\n"
"\n"
"  The link geometry is derived from the sample rate, the numerology and\n"
"  the packet size. Defaults describe radio/fhi_8 at mu=1, 122.88 Msps.\n"
"\n"
"  --rate <Msps>     sample rate            (default 122.88)\n"
"  --mu <n>          numerology 0..4        (default 1)\n"
"  --spp <n>         samples per packet     (default 1920)\n"
"  --bits <n>        sample width, 16 only  (default 16)\n"
"  --ethertype <hex> (default 0xaefe)\n"
"  --seq-base <0|1>  seq_id of the first cell (default 1)\n"
"  --hdr-off <n>     frame start to eCPRI header (default 14)\n"
"  --iq-off <n>      eCPRI header to IQ          (default 8)\n"
"  --version <n>     expected eCPRI version, -1 to skip (default 1)\n"
"  --msgtype <n>     expected message type,  -1 to skip (default 0)\n"
"  -c <file>         read the same keys from a file, key = value per line\n"
"\n"
"  e.g.  %s sfp1\n"
"        %s sfp1 bc:24:11:ec:73:d3=gNB c6:89:58:52:65:2d=FPGA\n"
"        %s eth2 --rate 61.44 --mu 0 --spp 960\n";

static void cfg_defaults(void)
{
    C.rate_hz = 122.88e6; C.mu = 1; C.spp = 1920; C.bits = 16;
    C.ethertype = 0xAEFE; C.seq_base = 1;
    C.hdr_off = 14; C.iq_off = 8; C.ver = 1; C.msgtype = 0;
}

static int cfg_derive(void)
{
    if (C.mu < 0 || C.mu > 4) { std::cerr << "mu must be 0..4\n"; return -1; }
    if (C.bits != 16) {
        std::cerr << "only 16-bit samples are supported; --bits " << C.bits
                  << " would need a different unpacking path, and shipping one "
                     "I cannot test would be worse than refusing\n";
        return -1;
    }
    if (C.spp <= 0) { std::cerr << "--spp must be positive\n"; return -1; }

    double sps = C.rate_hz / 1000.0 / (double)(1 << C.mu);
    if (fabs(sps - floor(sps + 0.5)) > 1e-6) {
        std::cerr << "sample rate " << C.rate_hz / 1e6 << " Msps at mu=" << C.mu
                  << " gives " << sps << " samples per slot, not a whole number\n";
        return -1;
    }
    C.sps = (int)(sps + 0.5);
    if (C.sps % C.spp) {
        std::cerr << C.sps << " samples per slot is not divisible by " << C.spp
                  << " samples per packet\n";
        return -1;
    }
    C.pps     = C.sps / C.spp;
    C.slots   = 10 * (1 << C.mu);
    C.cells   = C.pps * C.slots;
    C.cell_us = (double)C.spp / C.rate_hz * 1e6;
    C.slot_us = 1000.0 / (double)(1 << C.mu);
    C.full_scale = (double)(1 << (C.bits - 1));

    if (C.cells < 2 || C.cells > 65536) {
        std::cerr << "packets per frame works out at " << C.cells
                  << ", which a 16-bit seq_id cannot address\n";
        return -1;
    }
    if (C.seq_base != 0 && C.seq_base != 1) {
        std::cerr << "--seq-base must be 0 or 1\n"; return -1;
    }
    return 0;
}

static int cfg_set(const std::string &k, const std::string &v)
{
    if      (k == "rate")      C.rate_hz   = atof(v.c_str()) * 1e6;
    else if (k == "mu")        C.mu        = atoi(v.c_str());
    else if (k == "spp")       C.spp       = atoi(v.c_str());
    else if (k == "bits")      C.bits      = atoi(v.c_str());
    else if (k == "ethertype") C.ethertype = (unsigned)strtoul(v.c_str(), NULL, 0);
    else if (k == "seq-base")  C.seq_base  = atoi(v.c_str());
    else if (k == "hdr-off")   C.hdr_off   = atoi(v.c_str());
    else if (k == "iq-off")    C.iq_off    = atoi(v.c_str());
    else if (k == "version")   C.ver       = atoi(v.c_str());
    else if (k == "msgtype")   C.msgtype   = atoi(v.c_str());
    else { std::cerr << "unknown setting: " << k << "\n"; return -1; }
    return 0;
}

static int cfg_file(const char *path)
{
    std::ifstream f(path);
    if (!f) { std::cerr << "cannot open " << path << "\n"; return -1; }
    std::string line; int lineno = 0;
    while (std::getline(f, line)) {
        lineno++;
        size_t h = line.find('#');
        if (h != std::string::npos) line = line.substr(0, h);
        size_t eq = line.find('=');
        if (eq == std::string::npos) {
            if (line.find_first_not_of(" \t\r\n") != std::string::npos) {
                std::cerr << path << ":" << lineno << ": expected key = value\n";
                return -1;
            }
            continue;
        }
        std::string k = line.substr(0, eq), v = line.substr(eq + 1);
        const char *ws = " \t\r\n";
        k.erase(0, k.find_first_not_of(ws));
        if (k.find_last_not_of(ws) != std::string::npos) k.erase(k.find_last_not_of(ws) + 1);
        v.erase(0, v.find_first_not_of(ws));
        if (v.find_last_not_of(ws) != std::string::npos) v.erase(v.find_last_not_of(ws) + 1);
        if (k.empty()) continue;
        if (cfg_set(k, v)) { std::cerr << "  at " << path << ":" << lineno << "\n"; return -1; }
    }
    return 0;
}

/* ================================================================ constants */

#define FRAMES_PER_SEC    100.0f
#define STALE_US          500000ULL
#define BURST_FRAC        0.10f
#define BURST_FLOOR_LSB   8.0f
#define CORR_LOCK         0.55
#define CORR_TRACK_WIN    8
#define REF_ALPHA         0.02f

static uint64_t now_us(void)
{
    using namespace std::chrono;
    return (uint64_t)duration_cast<microseconds>(
               steady_clock::now().time_since_epoch()).count();
}

/* ===================================================================== lane */

typedef struct {
    unsigned char mac[6];
    char  label[24];
    int   named;
    char  title[88];

    /* capture thread only */
    std::vector<int16_t> mn, mx;
    std::vector<int32_t> si, sq;
    std::vector<uint8_t> seen;
    std::vector<float>   lo, hi, rlo, rhi, plo, phi, span, ref;
    int      have_ref, locked, last_shift;
    double   pos, pos0;
    int      track_init;
    uint64_t t0;
    uint32_t last_cell;
    int      started;

    /* published under mtx */
    std::mutex         mtx;
    std::vector<float> elo, ehi, eplo, ephi;
    float  dc_i, dc_q;
    int    peak_cell;
    float  peak_span, peak_abs;
    int    b0, b1, nburst;
    int    shift;
    double corr;
    int    elocked;

    std::atomic<uint32_t> cells;
    std::atomic<uint64_t> pkts, pps, last_us;
    std::atomic<bool>     reset, reacquire, drift_reset;
    std::atomic<double>   ppm, drift_secs;
} lane_t;

static lane_t g_lane[MAX_LANES];

/* Lanes are only ever appended, by the capture thread, and a lane's mac and
   label never change once it exists. The render thread reads g_nlanes and
   then touches only lanes below that index, so publishing the count last
   makes a new lane safe to read. */
static std::atomic<int>      g_nlanes(0);
static std::atomic<uint64_t> g_overflow(0);

static std::atomic<uint32_t> g_drop(0), g_ifdrop(0);
static std::atomic<uint64_t> g_bad(0), g_trunc(0);
static std::atomic<bool>     g_running(true);
static std::atomic<bool>     g_measure_dc(false);
static std::atomic<bool>     g_align(false);

static pcap_t *g_ph = NULL;

static bool  g_persist    = true;
static bool  g_autofit    = true;
static bool  g_cursors    = false;
static float g_afterglow  = 3.0f;
static float g_blank_secs = 3.0f;

static double g_cx[MAX_LANES][2];
static double g_cy[MAX_LANES][2];
static double g_span_hold[MAX_LANES];

static void lane_title(lane_t *L, int idx)
{
    char mac[20];
    snprintf(mac, sizeof mac, "%02x:%02x:%02x:%02x:%02x:%02x",
             L->mac[0], L->mac[1], L->mac[2], L->mac[3], L->mac[4], L->mac[5]);
    if (L->label[0]) snprintf(L->title, sizeof L->title, "%s   src %s", L->label, mac);
    else             snprintf(L->title, sizeof L->title, "src %s   (lane %d)", mac, idx);
}

static void lane_alloc(lane_t *L, int idx)
{
    const int N = C.cells;
    L->mn.assign(N, 0); L->mx.assign(N, 0);
    L->si.assign(N, 0); L->sq.assign(N, 0);
    L->seen.assign(N, 0);
    L->lo.assign(N, 0.f);  L->hi.assign(N, 0.f);
    L->rlo.assign(N, 0.f); L->rhi.assign(N, 0.f);
    L->plo.assign(N, 0.f); L->phi.assign(N, 0.f);
    L->span.assign(N, 0.f); L->ref.assign(N, 0.f);
    L->elo.assign(N, 0.f); L->ehi.assign(N, 0.f);
    L->eplo.assign(N, 0.f); L->ephi.assign(N, 0.f);
    L->have_ref = L->locked = L->last_shift = 0;
    L->pos = L->pos0 = 0.0; L->track_init = 0; L->t0 = 0;
    L->last_cell = 0; L->started = 0;
    L->dc_i = L->dc_q = 0.f;
    L->peak_cell = -1; L->peak_span = L->peak_abs = 0.f;
    L->b0 = L->b1 = -1; L->nburst = 0;
    L->shift = 0; L->corr = 0.0; L->elocked = 0;
    L->cells.store(0); L->pkts.store(0); L->pps.store(0); L->last_us.store(0);
    L->reset.store(false); L->reacquire.store(false); L->drift_reset.store(false);
    L->ppm.store(0.0); L->drift_secs.store(0.0);
    g_cx[idx][0] = 4.0;  g_cx[idx][1] = 8.0;
    g_cy[idx][0] = -0.1; g_cy[idx][1] = 0.1;
    g_span_hold[idx] = 1e-4;
}

/* capture thread only */
static lane_t *lane_for(const unsigned char *src)
{
    const int n = g_nlanes.load(std::memory_order_relaxed);
    for (int i = 0; i < n; i++)
        if (memcmp(g_lane[i].mac, src, 6) == 0) return &g_lane[i];

    if (n >= MAX_LANES) { g_overflow++; return NULL; }

    lane_t *L = &g_lane[n];
    memcpy(L->mac, src, 6);
    lane_title(L, n);
    g_nlanes.store(n + 1, std::memory_order_release);   /* publish last */
    return L;
}

/* Normalised circular cross-correlation. Returns the shift that best aligns
   x onto ref. window <= 0 searches every shift. Nothing is assumed about the
   shape of either signal. */
static int best_shift(const std::vector<float> &x, const std::vector<float> &ref,
                      int centre, int window, double *out_r)
{
    const int N = (int)x.size();
    double xs = 0, xs2 = 0, rs = 0, rs2 = 0;
    for (int i = 0; i < N; i++) {
        xs += x[i];   xs2 += (double)x[i] * x[i];
        rs += ref[i]; rs2 += (double)ref[i] * ref[i];
    }
    const double xm = xs / N, rm = rs / N;
    const double xv = xs2 / N - xm * xm, rv = rs2 / N - rm * rm;
    if (xv <= 1e-18 || rv <= 1e-18) { *out_r = 0.0; return 0; }

    const double denom = (double)N * sqrt(xv * rv);
    int    best_s = 0;
    double best_r = -2.0;
    int    lo, hi;
    if (window <= 0 || window >= N / 2) { lo = 0; hi = N - 1; }
    else                                { lo = centre - window; hi = centre + window; }

    for (int s = lo; s <= hi; s++) {
        int ss = s % N; if (ss < 0) ss += N;
        double acc = 0.0;
        int k = ss;
        for (int c = 0; c < N; c++) {
            acc += (double)x[c] * ref[k];
            if (++k == N) k = 0;
        }
        const double r = (acc - (double)N * xm * rm) / denom;
        if (r > best_r) { best_r = r; best_s = ss; }
    }
    *out_r = best_r;
    return best_s;
}

static void finish_frame(lane_t *L)
{
    const int N = C.cells;

    /* Re-acquiring implies clearing. The moment the correlation reference
       moves, the persistence band was accumulated at the old alignment and
       describes a position the trace no longer occupies - keeping it would
       show a band that is simply in the wrong place. */
    const bool reacq = L->reacquire.exchange(false);
    const bool clear = L->reset.exchange(false) || reacq;
    if (reacq) { L->have_ref = 0; L->locked = 0; }

    const float burst_floor = BURST_FLOOR_LSB / (float)C.full_scale;

    float k = 0.0f;
    if (g_afterglow > 0.01f)
        k = 1.0f - expf(-1.0f / (FRAMES_PER_SEC * g_afterglow));

    uint32_t have = 0;
    int64_t  tot_i = 0, tot_q = 0;
    int      peak_cell = -1;
    float    peak_span = 0.0f, peak_abs = 0.0f;

    for (int c = 0; c < N; c++) {
        have += L->seen[c];
        const float a = (float)L->mn[c] / (float)C.full_scale;
        const float b = (float)L->mx[c] / (float)C.full_scale;
        L->lo[c] = a; L->hi[c] = b;

        const float sp = b - a;
        L->span[c] = sp;
        if (sp > peak_span) { peak_span = sp; peak_cell = c; }
        if (fabsf(a) > peak_abs) peak_abs = fabsf(a);
        if (fabsf(b) > peak_abs) peak_abs = fabsf(b);

        tot_i += L->si[c]; tot_q += L->sq[c];
        L->mn[c] = 0; L->mx[c] = 0; L->si[c] = 0; L->sq[c] = 0;
    }
    std::fill(L->seen.begin(), L->seen.end(), (uint8_t)0);

    if (peak_span < burst_floor) { peak_cell = -1; peak_span = 0.0f; }

    int b0 = -1, b1 = -1, nburst = 0;
    if (peak_cell >= 0) {
        float thr = peak_span * BURST_FRAC;
        if (thr < burst_floor) thr = burst_floor;
        for (int c = 0; c < N; c++)
            if (L->span[c] >= thr) { if (b0 < 0) b0 = c; b1 = c; nburst++; }
    }

    int    shift = 0;
    double corr  = 0.0;

    if (peak_cell >= 0) {
        if (!L->have_ref) {
            L->ref = L->span;
            L->have_ref = 1; L->last_shift = 0;
            shift = 0; corr = 1.0; L->locked = 1;
        } else {
            const int win = L->locked ? CORR_TRACK_WIN : 0;
            shift = best_shift(L->span, L->ref, L->last_shift, win, &corr);
            L->locked = (corr >= CORR_LOCK);
            if (!L->locked && win) {
                shift = best_shift(L->span, L->ref, 0, 0, &corr);
                L->locked = (corr >= CORR_LOCK);
            }
        }
        if (L->locked) {
            int delta = shift - L->last_shift;
            if (delta >  N / 2) delta -= N;
            if (delta < -N / 2) delta += N;
            if (!L->track_init) {
                L->track_init = 1; L->pos = L->pos0 = 0.0; L->t0 = now_us();
            } else {
                L->pos += delta;
            }
            L->last_shift = shift;
            for (int c = 0; c < N; c++) {
                int s = c + shift; if (s >= N) s -= N;
                L->ref[c] += (L->span[s] - L->ref[c]) * REF_ALPHA;
            }
        }
    } else {
        L->locked = 0;
    }

    const uint64_t now = now_us();
    if (L->drift_reset.exchange(false)) { L->pos0 = L->pos; L->t0 = now; }
    if (L->track_init && now > L->t0) {
        const double secs = (double)(now - L->t0) / 1e6;
        /* one cell lasts cell_us microseconds, so cells per second is ppm */
        L->ppm.store((L->pos - L->pos0) * C.cell_us / secs);
        L->drift_secs.store(secs);
    }

    const int disp_shift = (g_align.load() && L->locked) ? shift : 0;
    const std::vector<float> *slo = &L->lo, *shi = &L->hi;
    if (disp_shift) {
        for (int c = 0; c < N; c++) {
            int s = c + disp_shift; if (s >= N) s -= N;
            L->rlo[c] = L->lo[s]; L->rhi[c] = L->hi[s];
        }
        slo = &L->rlo; shi = &L->rhi;
    }

    /* persistence updated AFTER the rotation, so an aligned display keeps a
       sharp band instead of smearing over every position the burst visited */
    for (int c = 0; c < N; c++) {
        const float a = (*slo)[c], b = (*shi)[c];
        if (clear) { L->plo[c] = a; L->phi[c] = b; }
        else {
            L->phi[c] = (b > L->phi[c]) ? b : L->phi[c] + (b - L->phi[c]) * k;
            L->plo[c] = (a < L->plo[c]) ? a : L->plo[c] + (a - L->plo[c]) * k;
        }
    }

    const double n = (double)N * (double)C.spp;
    {
        std::lock_guard<std::mutex> lk(L->mtx);
        L->elo = *slo; L->ehi = *shi;
        L->eplo = L->plo; L->ephi = L->phi;
        L->dc_i = (float)((double)tot_i / n);
        L->dc_q = (float)((double)tot_q / n);
        L->peak_cell = peak_cell; L->peak_span = peak_span; L->peak_abs = peak_abs;
        L->b0 = b0; L->b1 = b1; L->nburst = nburst;
        L->shift = disp_shift; L->corr = corr; L->elocked = L->locked;
    }
    L->cells.store(have);
    L->last_us.store(now);
}

/* hot path: one pass over the samples, integer compares only */
static void on_packet(unsigned char *user, const struct pcap_pkthdr *h,
                      const unsigned char *bytes)
{
    (void)user;

    const int need = C.hdr_off + C.iq_off + C.spp * 4;
    if ((int)h->caplen < need) { g_trunc++; return; }

    const unsigned char *b = bytes + C.hdr_off;
    if (C.ver >= 0 && ((b[0] >> 4) & 0x0F) != C.ver)        { g_bad++; return; }
    if (C.msgtype >= 0 && b[1] != (unsigned char)C.msgtype) { g_bad++; return; }

    uint16_t v;
    memcpy(&v, b + 6, 2);
    const int seq = (int)ntohs(v);
    if (seq < C.seq_base || seq >= C.seq_base + C.cells) { g_bad++; return; }

    const uint32_t cell = (uint32_t)(seq - C.seq_base);

    /* the source address alone decides the lane - no inference about which
       end of the link a sender is on, so a second transmitter cannot land
       in someone else's sequence */
    lane_t *L = lane_for(bytes + 6);
    if (!L) return;

    L->pkts.fetch_add(1, std::memory_order_relaxed);

    /* a real frame wrap is a large backward jump; a small one is a
       reordering and must not cut the frame in two */
    if (L->started && cell < L->last_cell &&
        L->last_cell - cell > (uint32_t)(C.cells / 2)) finish_frame(L);
    L->started   = 1;
    L->last_cell = cell;

    const int16_t *iq = (const int16_t *)(b + C.iq_off);
    const int      ns = C.spp;

    int16_t mn = 0, mx = 0;

    if (g_measure_dc.load(std::memory_order_relaxed)) {
        int32_t si = 0, sq = 0;
        for (int i = 0; i < ns; i++) {
            const int16_t I = iq[2 * i], Q = iq[2 * i + 1];
            if (I < mn) mn = I;
            if (I > mx) mx = I;
            si += I; sq += Q;
        }
        L->si[cell] = si; L->sq[cell] = sq;
    } else {
        for (int i = 0; i < ns; i++) {
            const int16_t I = iq[2 * i];
            if (I < mn) mn = I;
            if (I > mx) mx = I;
        }
        L->si[cell] = 0; L->sq[cell] = 0;
    }

    L->mn[cell] = mn; L->mx[cell] = mx; L->seen[cell] = 1;
}

static void stats_thread()
{
    struct pcap_stat st;
    uint32_t pd = 0, pi = 0;
    uint64_t prev[MAX_LANES] = { 0 };
    while (g_running.load()) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        if (g_ph && pcap_stats(g_ph, &st) == 0) {
            g_drop.store(st.ps_drop - pd);
            g_ifdrop.store(st.ps_ifdrop - pi);
            pd = st.ps_drop; pi = st.ps_ifdrop;
        }
        const int n = g_nlanes.load(std::memory_order_acquire);
        for (int i = 0; i < n; i++) {
            const uint64_t now = g_lane[i].pkts.load(std::memory_order_relaxed);
            g_lane[i].pps.store(now - prev[i]);
            prev[i] = now;
        }
    }
}

static void capture_thread(const char *iface)
{
    char err[PCAP_ERRBUF_SIZE] = {0};
    g_ph = pcap_create(iface, err);
    if (!g_ph) { std::cerr << "pcap_create: " << err << "\n"; return; }

    pcap_set_snaplen(g_ph, C.hdr_off + C.iq_off + C.spp * 4 + 64);
    pcap_set_promisc(g_ph, 1);
    pcap_set_timeout(g_ph, 10);
    pcap_set_buffer_size(g_ph, 256 * 1024 * 1024);

    if (pcap_activate(g_ph) < 0) {
        std::cerr << "pcap_activate: " << pcap_geterr(g_ph) << "\n";
        return;
    }

    char filt[64];
    snprintf(filt, sizeof filt, "ether proto 0x%04x", C.ethertype & 0xffff);
    struct bpf_program fp;
    if (pcap_compile(g_ph, &fp, filt, 1, PCAP_NETMASK_UNKNOWN) == 0) {
        pcap_setfilter(g_ph, &fp);
        pcap_freecode(&fp);
    }
    pcap_loop(g_ph, -1, on_packet, NULL);
}

static void glfwErrorCallback(int e, const char *d)
{
    std::cerr << "GLFW error " << e << ": " << d << '\n';
}

/* ==================================================================== draw */

static std::vector<double> g_xs, g_grid, g_lo, g_hi, g_plo, g_phi, g_mid;
static std::vector<double> g_tick_pos;
static std::vector<std::string>  g_tick_str;
static std::vector<const char *> g_tick_lbl;

static void draw_lane(lane_t *L, int idx, ImVec4 col, bool show_x,
                      bool stale, bool blank)
{
    const int N = C.cells;

    if (blank) {
        std::fill(g_lo.begin(), g_lo.end(), 0.0);
        std::fill(g_hi.begin(), g_hi.end(), 0.0);
        std::fill(g_plo.begin(), g_plo.end(), 0.0);
        std::fill(g_phi.begin(), g_phi.end(), 0.0);
        std::fill(g_mid.begin(), g_mid.end(), 0.0);
        g_span_hold[idx] = 1e-4;
    } else {
        std::lock_guard<std::mutex> lk(L->mtx);
        for (int c = 0; c < N; c++) {
            g_lo[c]  = L->elo[c];  g_hi[c]  = L->ehi[c];
            g_plo[c] = L->eplo[c]; g_phi[c] = L->ephi[c];
        }
    }

    if (stale) { col.x *= 0.35f; col.y *= 0.35f; col.z *= 0.35f; }

    double target = 1e-6;
    for (int c = 0; c < N; c++) {
        if (fabs(g_hi[c]) > target) target = fabs(g_hi[c]);
        if (fabs(g_lo[c]) > target) target = fabs(g_lo[c]);
        if (g_persist) {
            if (fabs(g_phi[c]) > target) target = fabs(g_phi[c]);
            if (fabs(g_plo[c]) > target) target = fabs(g_plo[c]);
        }
    }
    if (target < 1e-4) target = 1e-4;
    target *= 1.15;

    double *S = &g_span_hold[idx];
    *S = (target > *S) ? target : *S + (target - *S) * 0.05;
    const double span = *S;

    ImPlotAxisFlags xf = ImPlotAxisFlags_Lock;
    if (!show_x) xf |= ImPlotAxisFlags_NoTickLabels;

    const char *xlabel = NULL;
    if (show_x) xlabel = g_align.load() ? "slot (aligned)" : "slot";

    if (ImPlot::BeginPlot(L->title, ImVec2(-1, -1), ImPlotFlags_NoLegend)) {
        ImPlot::SetupAxes(xlabel, "amplitude", xf, ImPlotAxisFlags_Lock);
        ImPlot::SetupAxisLimits(ImAxis_X1, 0, C.slots, ImPlotCond_Always);
        ImPlot::SetupAxisLimits(ImAxis_Y1,
                                g_autofit ? -span : -1.0,
                                g_autofit ?  span :  1.0, ImPlotCond_Always);
        ImPlot::SetupAxisTicks(ImAxis_X1, g_tick_pos.data(), C.slots,
                               g_tick_lbl.data());

        ImPlot::SetNextLineStyle(ImVec4(0.45f, 0.45f, 0.45f, 0.30f), 1.0f);
        ImPlot::PlotInfLines("##grid", g_grid.data(), C.slots + 1);

        if (!blank) {
            if (g_persist) {
                ImPlot::SetNextFillStyle(col, 0.20f);
                ImPlot::PlotShaded("##persist", g_xs.data(), g_plo.data(),
                                   g_phi.data(), N);
            }
            ImPlot::SetNextFillStyle(col, 1.0f);
            ImPlot::PlotShaded("##env", g_xs.data(), g_lo.data(), g_hi.data(), N);
            for (int c = 0; c < N; c++) g_mid[c] = 0.5 * (g_lo[c] + g_hi[c]);
            ImPlot::SetNextLineStyle(col, 1.6f);
            ImPlot::PlotLine("##mid", g_xs.data(), g_mid.data(), N);
        }

        if (g_cursors) {
            const ImVec4 cxc(0.95f, 0.35f, 0.35f, 1.0f);
            const ImVec4 cyc(0.45f, 0.65f, 1.00f, 1.0f);
            ImPlot::DragLineX(idx * 10 + 0, &g_cx[idx][0], cxc, 1.5f);
            ImPlot::DragLineX(idx * 10 + 1, &g_cx[idx][1], cxc, 1.5f);
            ImPlot::DragLineY(idx * 10 + 2, &g_cy[idx][0], cyc, 1.5f);
            ImPlot::DragLineY(idx * 10 + 3, &g_cy[idx][1], cyc, 1.5f);
        }
        ImPlot::EndPlot();
    }
}

/* Every status block is exactly LANE_LINES tall, whatever it has to say.
   Lines appearing and disappearing - a lane losing lock, going stale, a
   burst coming and going - changed the header height frame to frame, and
   since the plots fill whatever space is left, the whole display jumped. */
#define LANE_LINES 3

static void pad_to(int used)
{
    for (int i = used; i < LANE_LINES; i++) ImGui::TextUnformatted(" ");
}

static void lane_status(lane_t *L, int idx, ImVec4 col, uint64_t now, bool blank)
{
    const uint64_t last = L->last_us.load();
    if (last == 0) {
        ImGui::TextColored(ImVec4(0.6f, 0.6f, 0.6f, 1),
                           "  %-30s no frame yet", L->title);
        pad_to(1);
        return;
    }
    const uint64_t age = now - last;

    if (blank) {
        ImGui::TextColored(ImVec4(0.6f, 0.6f, 0.6f, 1),
                           "  %-30s NO SIGNAL  -- quiet for %.0f s, cleared",
                           L->title, age / 1e6);
        pad_to(1);
        return;
    }
    if (age > STALE_US) {
        ImGui::TextColored(ImVec4(1, 0.55f, 0.25f, 1),
                           "  %-30s STALE %.1f s  -- last frame, not live",
                           L->title, age / 1e6);
        pad_to(1);
        return;
    }

    float dci, dcq, pabs;
    int   pc, b0, b1, nb, sh, lk;
    double cr;
    {
        std::lock_guard<std::mutex> lk2(L->mtx);
        dci = L->dc_i; dcq = L->dc_q; pabs = L->peak_abs;
        pc = L->peak_cell; b0 = L->b0; b1 = L->b1; nb = L->nburst;
        sh = L->shift; cr = L->corr; lk = L->elocked;
    }

    char dcbuf[72] = "";
    if (g_measure_dc.load())
        snprintf(dcbuf, sizeof dcbuf, "   DC I=%+.0f Q=%+.0f (%.2f%% FS)",
                 dci, dcq,
                 100.0 * sqrt((double)dci * dci + (double)dcq * dcq) / C.full_scale);

    ImGui::TextColored(col, "  %-30s %u/%d cells   %llu pkt/s   peak %.4f%s",
                       L->title, L->cells.load(), C.cells,
                       (unsigned long long)L->pps.load(), pabs, dcbuf);

    if (pc < 0) {
        ImGui::TextColored(ImVec4(0.6f, 0.6f, 0.6f, 1),
                           "      no burst above the noise floor");
        pad_to(2);
        return;
    }

    /* The peak cell is deliberately not shown. With more than one burst it
       just names whichever happens to be tallest this frame, which is the
       same single-point fragility that made peak-latched triggering
       useless. It is still computed, as the gate that decides whether
       there is a burst at all. */
    const double w = (double)(b1 - b0 + 1);
    ImGui::Text("      burst %d..%d = slot %.2f..%.2f   width %.0f us (%d cells)"
                "   duty %.1f%%",
                b0, b1, b0 / (double)C.pps, (b1 + 1) / (double)C.pps,
                w * C.cell_us, (int)w, 100.0 * nb / (double)C.cells);

    if (!lk) {
        ImGui::TextColored(ImVec4(1, 0.55f, 0.25f, 1),
                           "      NO LOCK (corr %.2f) -- no repeating pattern "
                           "to align to; drift not measurable", cr);
        pad_to(3);
        return;
    }

    const double ppm  = L->ppm.load();
    const double secs = L->drift_secs.load();
    const ImVec4 pcol = (secs < 30.0) ? ImVec4(0.65f, 0.65f, 0.65f, 1)
                                      : ImVec4(1.0f, 0.8f, 0.3f, 1);
    ImGui::TextColored(pcol,
        "      lock corr %.2f  shift %d cells   drift %+.3f ppm over %.0f s%s",
        cr, sh, ppm, secs, (secs < 30.0) ? "  (too short to trust)" : "");

    /* the reset sits next to the number it resets, and is per lane - drift
       is a slow measurement and restarting one sender's baseline should not
       disturb another's */
    ImGui::SameLine();
    ImGui::PushID(idx);
    if (ImGui::SmallButton("reset")) L->drift_reset.store(true);
    ImGui::PopID();
}

static void cursor_readout(lane_t *L, int idx)
{
    const double x0 = g_cx[idx][0], x1 = g_cx[idx][1];
    const double y0 = g_cy[idx][0], y1 = g_cy[idx][1];
    const double dx = fabs(x1 - x0), dy = fabs(y1 - y0);
    const double dt_us = dx * C.slot_us;

    char rate[48] = "";
    if (dt_us > 1e-9) {
        const double hz = 1e6 / dt_us;
        if (hz >= 1000.0) snprintf(rate, sizeof rate, "   1/dt = %.3f kHz", hz / 1000.0);
        else              snprintf(rate, sizeof rate, "   1/dt = %.1f Hz", hz);
    }
    ImGui::Text("  %-18s cursors  x %.3f .. %.3f slot  dx %.3f = %.1f us "
                "= %.0f samples = %.1f packets%s   |   dy %.5f = %.0f counts",
                L->label[0] ? L->label : "lane", x0, x1, dx, dt_us,
                dx * (double)C.pps * C.spp, dx * (double)C.pps, rate,
                dy, dy * C.full_scale);
}

static int parse_mac(const char *s, unsigned char out[6])
{
    unsigned int m[6];
    if (sscanf(s, "%x:%x:%x:%x:%x:%x", &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]) != 6)
        return 0;
    for (int i = 0; i < 6; i++) out[i] = (unsigned char)m[i];
    return 1;
}

int main(int argc, char **argv)
{
    cfg_defaults();

    if (argc < 2) {
        fprintf(stderr, USAGE, argv[0], MAX_LANES, argv[0], argv[0], argv[0]);
        return 1;
    }
    const char *iface = argv[1];

    std::vector<std::string> named;
    for (int a = 2; a < argc; a++) {
        std::string k = argv[a];
        if (k == "-c") {
            if (a + 1 >= argc) { std::cerr << "-c needs a file\n"; return 1; }
            if (cfg_file(argv[++a])) return 1;
        } else if (k.size() > 2 && k[0] == '-' && k[1] == '-') {
            if (a + 1 >= argc) { std::cerr << k << " needs a value\n"; return 1; }
            if (cfg_set(k.substr(2), argv[++a])) return 1;
        } else {
            named.push_back(k);
        }
    }

    if (cfg_derive()) return 1;

    for (int i = 0; i < MAX_LANES; i++) lane_alloc(&g_lane[i], i);

    int n = 0;
    for (size_t j = 0; j < named.size() && n < MAX_LANES; j++) {
        const std::string &s = named[j];
        const size_t eq = s.find('=');
        const std::string macs = (eq == std::string::npos) ? s : s.substr(0, eq);
        const std::string lab  = (eq == std::string::npos) ? "" : s.substr(eq + 1);
        if (!parse_mac(macs.c_str(), g_lane[n].mac)) {
            std::cerr << "bad MAC: " << macs << "\n";
            fprintf(stderr, USAGE, argv[0], MAX_LANES, argv[0], argv[0], argv[0]);
            return 1;
        }
        snprintf(g_lane[n].label, sizeof g_lane[n].label, "%s", lab.c_str());
        g_lane[n].named = 1;
        lane_title(&g_lane[n], n);
        n++;
    }
    if (named.size() > (size_t)MAX_LANES)
        std::cerr << "warning: only the first " << MAX_LANES
                  << " named senders are used\n";
    g_nlanes.store(n);

    std::cerr << "link: " << C.rate_hz / 1e6 << " Msps, mu=" << C.mu
              << ", " << C.spp << " samples/packet\n"
              << "  -> " << C.sps << " samples/slot, " << C.pps
              << " packets/slot, " << C.slots << " slots/frame, "
              << C.cells << " packets/frame\n"
              << "  -> cell " << C.cell_us << " us, slot " << C.slot_us
              << " us, " << C.cells * 100 << " packets/s per sender\n"
              << "lanes: " << n << " named, up to " << MAX_LANES
              << " discovered\n";

    const int N = C.cells;
    g_xs.resize(N); g_lo.resize(N); g_hi.resize(N);
    g_plo.resize(N); g_phi.resize(N); g_mid.resize(N);
    for (int c = 0; c < N; c++) g_xs[c] = (double)c / (double)C.pps;
    g_grid.resize(C.slots + 1);
    for (int s = 0; s <= C.slots; s++) g_grid[s] = s;
    g_tick_pos.resize(C.slots); g_tick_str.resize(C.slots); g_tick_lbl.resize(C.slots);
    for (int s = 0; s < C.slots; s++) {
        g_tick_pos[s] = s + 0.5;
        g_tick_str[s] = std::to_string(s);
        g_tick_lbl[s] = g_tick_str[s].c_str();
    }

    glfwSetErrorCallback(glfwErrorCallback);
    if (!glfwInit()) { std::cerr << "glfwInit failed\n"; return 1; }
    glfwDefaultWindowHints();
    GLFWwindow *window = glfwCreateWindow(1500, 980,
                                          "Split 8 fronthaul scope", nullptr, nullptr);
    if (!window) { std::cerr << "no window - is DISPLAY set?\n"; glfwTerminate(); return 1; }
    glfwMakeContextCurrent(window);
    glfwSwapInterval(1);
    if (glewInit() != GLEW_OK) { std::cerr << "glewInit failed\n"; return 1; }

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImPlot::CreateContext();
    ImGui::StyleColorsDark();
    ImGui::GetIO().FontGlobalScale = 1.15f;

    ImGui_ImplGlfw_InitForOpenGL(window, true);
    ImGui_ImplOpenGL3_Init("#version 130");

    std::thread cap(capture_thread, iface);
    std::thread sta(stats_thread);

    const ImVec4 COL[MAX_LANES] = {
        ImVec4(1.00f, 0.85f, 0.10f, 1.0f),   /* scope yellow */
        ImVec4(0.20f, 0.95f, 0.35f, 1.0f),   /* scope green  */
        ImVec4(0.40f, 0.70f, 1.00f, 1.0f),   /* blue         */
        ImVec4(1.00f, 0.45f, 0.75f, 1.0f),   /* pink         */
        ImVec4(1.00f, 0.55f, 0.15f, 1.0f),   /* orange       */
        ImVec4(0.70f, 0.60f, 1.00f, 1.0f),   /* violet       */
    };

    while (!glfwWindowShouldClose(window)) {
        glfwPollEvents();
        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplGlfw_NewFrame();
        ImGui::NewFrame();

        const ImGuiViewport *vp = ImGui::GetMainViewport();
        ImGui::SetNextWindowPos(vp->WorkPos);
        ImGui::SetNextWindowSize(vp->WorkSize);
        ImGui::Begin("scope", NULL,
                     ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize |
                     ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoCollapse);

        const int      lanes = g_nlanes.load(std::memory_order_acquire);
        const uint64_t now   = now_us();
        const uint32_t drop  = g_drop.load(), ifdrop = g_ifdrop.load();
        const uint64_t blank_us = (uint64_t)(g_blank_secs * 1e6);

        bool stale[MAX_LANES] = { false }, blank[MAX_LANES] = { false };
        uint64_t total_pps = 0;
        for (int i = 0; i < lanes; i++) {
            const uint64_t last = g_lane[i].last_us.load();
            const uint64_t age  = last ? now - last : 0;
            stale[i] = last && age > STALE_US;
            blank[i] = last && age > blank_us;
            total_pps += g_lane[i].pps.load();
        }
        const double gbps = (double)total_pps *
                            (double)(C.hdr_off + C.iq_off + C.spp * 4) * 8.0 / 1e9;

        ImGui::Text("%s   %d sender%s   |   %.2f Msps  mu=%d  %d sam/pkt  "
                    "%d pkt/slot  %d slots  %d cells/frame",
                    iface, lanes, lanes == 1 ? "" : "s",
                    C.rate_hz / 1e6, C.mu, C.spp, C.pps, C.slots, C.cells);

        if (drop || ifdrop)
            ImGui::TextColored(ImVec4(1, 0.25f, 0.25f, 1),
                               "LOSSY  drop=+%u ifdrop=+%u   -- traces have holes",
                               drop, ifdrop);
        else
            ImGui::TextColored(ImVec4(0.3f, 1, 0.3f, 1), "clean  drop=0 ifdrop=0");

        /* drop and ifdrop are blind to loss inside the switch. If the senders'
           combined rate approaches the mirror port's line rate, cells can sit
           below full on a capture that calls itself clean. */
        ImGui::Text("%llu pkt/s   %.2f Gbit/s on the mirror   bad=%llu trunc=%llu",
                    (unsigned long long)total_pps, gbps,
                    (unsigned long long)g_bad.load(),
                    (unsigned long long)g_trunc.load());

        for (int i = 0; i < lanes; i++)
            lane_status(&g_lane[i], i, COL[i % MAX_LANES], now, blank[i]);

        /* always drawn, even when empty, so the header height never changes */
        const uint64_t ovf = g_overflow.load();
        if (ovf)
            ImGui::TextColored(ImVec4(1, 0.8f, 0.3f, 1),
                               "  more than %d senders -- %llu packets ignored "
                               "rather than folded into another lane",
                               MAX_LANES, (unsigned long long)ovf);
        else
            ImGui::TextUnformatted(" ");

        if (g_cursors)
            for (int i = 0; i < lanes; i++) cursor_readout(&g_lane[i], i);

        ImGui::Checkbox("persistence", &g_persist);
        ImGui::SameLine();
        if (ImGui::Button("clear"))
            for (int i = 0; i < lanes; i++) g_lane[i].reset.store(true);
        ImGui::SameLine();
        ImGui::Checkbox("auto range", &g_autofit);
        ImGui::SameLine();
        ImGui::SetNextItemWidth(170);
        ImGui::SliderFloat("afterglow", &g_afterglow, 0.0f, 20.0f,
                           g_afterglow < 0.01f ? "hold" : "%.1f s");
        ImGui::SameLine();
        ImGui::SetNextItemWidth(170);
        ImGui::SliderFloat("blank after", &g_blank_secs, 1.0f, 30.0f, "%.0f s");

        bool al = g_align.load();
        if (ImGui::Checkbox("align", &al)) g_align.store(al);
        ImGui::SameLine();
        /* re-acquire clears persistence too - see finish_frame */
        if (ImGui::Button("re-acquire"))
            for (int i = 0; i < lanes; i++) g_lane[i].reacquire.store(true);
        ImGui::SameLine();
        ImGui::Checkbox("cursors", &g_cursors);
        ImGui::SameLine();
        bool dc = g_measure_dc.load();
        if (ImGui::Checkbox("measure DC", &dc)) g_measure_dc.store(dc);

        if (lanes == 0) {
            ImGui::Dummy(ImVec2(0, 20));
            ImGui::TextColored(ImVec4(1, 0.8f, 0.3f, 1), "no eCPRI frames yet.");
            ImGui::TextWrapped(
                "Check the interface is up, promiscuous and has an MTU large "
                "enough for the frame, and that the mirror is carrying this "
                "ethertype:  sudo tcpdump -i %s -nn -e -c 5 'ether proto 0x%04x'",
                iface, C.ethertype & 0xffff);
        } else if (ImPlot::BeginSubplots("##stack", lanes, 1, ImVec2(-1, -1),
                                         ImPlotSubplotFlags_LinkCols)) {
            for (int i = 0; i < lanes; i++)
                draw_lane(&g_lane[i], i, COL[i % MAX_LANES],
                          i == lanes - 1, stale[i], blank[i]);
            ImPlot::EndSubplots();
        }

        ImGui::End();
        ImGui::Render();
        int w, h;
        glfwGetFramebufferSize(window, &w, &h);
        glViewport(0, 0, w, h);
        glClearColor(0.04f, 0.05f, 0.06f, 1.00f);
        glClear(GL_COLOR_BUFFER_BIT);
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
        glfwSwapBuffers(window);
    }

    g_running.store(false);
    if (g_ph) pcap_breakloop(g_ph);
    cap.join();
    sta.join();
    if (g_ph) pcap_close(g_ph);

    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplGlfw_Shutdown();
    ImPlot::DestroyContext();
    ImGui::DestroyContext();
    glfwDestroyWindow(window);
    glfwTerminate();
    return 0;
}
