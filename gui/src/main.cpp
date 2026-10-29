/* -------------------------------------------------------------------------
 * Split 8 fronthaul scope
 *
 * Draws what a digital oscilloscope draws: a min/max envelope of the raw
 * waveform, in linear amplitude, about a true zero baseline. For each
 * eCPRI packet the smallest and largest I sample are kept and the band
 * between them is filled - the same decimation a scope does per pixel
 * column. Two stacked plots share the slot axis; each lane has its own Y
 * axis, because an uplink typically sits 30-40 dB below a downlink.
 *
 * ---------------------------------------------------------------------
 * WHAT CHANGED IN THIS REVISION, AND WHY
 *
 * The previous version hardcoded twelve things, every one of them true
 * only of radio/fhi_8 at mu=1 and 122.88 Msps:
 *
 *   samples/packet 1920   packets/slot 32    slots/frame 20
 *   packets/frame  640    full scale 32768   cell 15.625 us
 *   ethertype 0xAEFE      eCPRI version 1    msg_type 0x00
 *   seq_id = cell + 1     header at 14 + 8   I/Q int16 interleaved
 *
 * Point that at mu=0, or a 61.44 Msps link, or a sender that numbers its
 * packets from 0, and nothing holds. So none of it is defined any more -
 * it is DERIVED from four numbers, with the wire layout as flags:
 *
 *   samples/slot   = sample_rate / 1000 / 2^mu
 *   packets/slot   = samples_per_slot / samples_per_packet
 *   slots/frame    = 10 * 2^mu
 *   packets/frame  = packets_per_slot * slots_per_frame
 *   cell duration  = samples_per_packet / sample_rate
 *
 * A link is now described on the command line or in a config file rather
 * than compiled in, and the geometry is checked for consistency at start
 * instead of silently producing a wrong axis.
 *
 * ALIGNMENT IS NOW CROSS-CORRELATION, NOT PEAK-FINDING
 *
 * The previous trigger latched onto the single highest-energy cell. That
 * only works when there is one dominant burst. Given four comparable
 * bursts - slots 0, 2, 10 and 13 is a perfectly ordinary frame - the peak
 * hops between them and the display jitters instead of locking.
 *
 * This version correlates each frame's envelope against a slowly adapted
 * reference and takes the shift that maximises it:
 *
 *   r(s) = sum_c  x[c] * ref[(c + s) mod N],  normalised
 *
 * which assumes nothing about the signal's shape. One burst, four bursts,
 * or a broad continuous waveform all align on their whole structure. And
 * it fails honestly: a flat correlation surface means there is no
 * repeating pattern, so it reports NO LOCK rather than locking onto
 * noise. Peak-finding cannot tell those two cases apart.
 *
 * Full search while unlocked, +/- a few cells once tracking. 640x640 is
 * 410k multiply-adds per lane per frame - 82 M/s at 100 frames/s.
 *
 * ALIGNMENT AND DRIFT ARE SEPARATE
 *
 * The shift is computed every frame whether or not you are using it to
 * steady the display. Drift in ppm comes from the accumulated shift and
 * is reported always; alignment only decides whether the display is
 * rotated by it. Free-run is the default, because on a link with no drift
 * there is nothing to align and the feature can only misbehave.
 *
 * KEPT FROM THE PREVIOUS REVISION
 *
 *   Persistence is a phosphor with a settable afterglow, not a high-water
 *   mark. Completed frames are published under a mutex so the renderer
 *   never sees half of one frame and half of the next. The Y axis rises
 *   at once and falls slew-limited. A lane that stops transmitting dims,
 *   then blanks, instead of showing a ghost frame for ever. Cursors,
 *   per-lane measurements, optional DC mean, bad/trunc counters.
 *
 * KNOWN LIMITATION, UNCHANGED
 *
 *   The trace is min/max of I only. Q is read for the DC mean and is not
 *   plotted. The true envelope is sqrt(I^2 + Q^2); I alone swings through
 *   zero on every carrier cycle even when the envelope is flat. The
 *   correlation keys on the per-packet span (hi - lo), which brackets the
 *   whole swing and is far less phase-sensitive than I itself.
 *
 * Run:  ./build/src/imgui_app <iface> <dl-src-mac> [options]
 *       sudo setcap "cap_net_raw,cap_net_admin=eip" ./build/src/imgui_app
 *       (repeat setcap after every rebuild; do NOT run with sudo)
 * ---------------------------------------------------------------------- */

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
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

/* ============================================================== link config */

typedef struct {
    /* given */
    double   rate_hz;        /* sample rate                                 */
    int      mu;             /* numerology                                  */
    int      spp;            /* samples per packet                          */
    int      bits;           /* sample width                                */
    unsigned ethertype;
    int      seq_base;       /* seq_id of the first cell: 0 or 1            */
    int      hdr_off;        /* frame start -> eCPRI header                 */
    int      iq_off;         /* eCPRI header start -> IQ                    */
    int      ver;            /* expected eCPRI version, -1 to skip          */
    int      msgtype;        /* expected message type, -1 to skip           */

    /* derived */
    int      sps;            /* samples per slot                            */
    int      pps;            /* packets per slot                            */
    int      slots;          /* slots per frame                             */
    int      cells;          /* packets per frame                           */
    double   cell_us;
    double   slot_us;
    double   full_scale;
} cfg_t;

static cfg_t C;

static const char *USAGE =
"usage: %s <iface> <dl-src-mac> [options]\n"
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
"  -c <file>         read the same keys from a file, one key = value per\n"
"                    line, # for comments\n"
"\n"
"  e.g.  %s sfp1 c6:89:58:52:65:2d\n"
"        %s eth2 aa:bb:cc:dd:ee:ff --rate 61.44 --mu 0 --spp 960\n";

static void cfg_defaults(void)
{
    C.rate_hz   = 122.88e6;
    C.mu        = 1;
    C.spp       = 1920;
    C.bits      = 16;
    C.ethertype = 0xAEFE;
    C.seq_base  = 1;
    C.hdr_off   = 14;
    C.iq_off    = 8;
    C.ver       = 1;
    C.msgtype   = 0;
}

/* returns 0 on success, prints its own complaint on failure */
static int cfg_derive(void)
{
    if (C.mu < 0 || C.mu > 4) {
        std::cerr << "mu must be 0..4\n"; return -1;
    }
    if (C.bits != 16) {
        std::cerr << "only 16-bit samples are supported; --bits " << C.bits
                  << " would need a different unpacking path, and shipping "
                     "one I cannot test would be worse than refusing\n";
        return -1;
    }
    if (C.spp <= 0) { std::cerr << "--spp must be positive\n"; return -1; }

    double sps = C.rate_hz / 1000.0 / (double)(1 << C.mu);
    if (fabs(sps - floor(sps + 0.5)) > 1e-6) {
        std::cerr << "sample rate " << C.rate_hz / 1e6 << " Msps at mu=" << C.mu
                  << " gives " << sps << " samples per slot, which is not a "
                     "whole number\n";
        return -1;
    }
    C.sps = (int)(sps + 0.5);

    if (C.sps % C.spp) {
        std::cerr << C.sps << " samples per slot is not divisible by "
                  << C.spp << " samples per packet\n";
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
                  << ", which cannot be addressed by a 16-bit seq_id\n";
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
    std::string line;
    int lineno = 0;
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

#define FRAMES_PER_SEC    100.0f      /* radio frames per second, always      */
#define STALE_US          500000ULL

#define BURST_FRAC        0.10f
#define BURST_FLOOR_LSB   8.0f

#define CORR_LOCK         0.55        /* correlation above this counts as lock */
#define CORR_TRACK_WIN    8           /* +/- cells searched once locked        */
#define REF_ALPHA         0.02f       /* reference adaptation rate             */

static uint64_t now_us(void)
{
    using namespace std::chrono;
    return (uint64_t)duration_cast<microseconds>(
               steady_clock::now().time_since_epoch()).count();
}

/* ====================================================== shared with the UI */

typedef struct {
    std::vector<float> lo, hi;      /* live envelope, as displayed */
    std::vector<float> plo, phi;    /* persistence                 */
    float dc_i, dc_q;

    /* measurements, in TRUE cell indices - never rotated */
    int   peak_cell;
    float peak_span, peak_abs;
    int   b0, b1, nburst;

    int    shift;                   /* cells the display was rotated by */
    double corr;                    /* correlation at that shift        */
    int    locked;
} env_t;

static env_t      g_env[2];
static std::mutex g_env_mtx[2];

static std::atomic<uint32_t> g_cellcount[2];
static std::atomic<uint64_t> g_last_us[2];
static std::atomic<uint32_t> g_drop(0), g_ifdrop(0);
static std::atomic<uint64_t> g_bad(0), g_trunc(0);
static std::atomic<bool>     g_running(true);
static std::atomic<bool>     g_measure_dc(false);

static std::atomic<bool>   g_align(false);        /* rotate the display */
static std::atomic<bool>   g_reacquire[2];
static std::atomic<double> g_ppm[2];
static std::atomic<double> g_drift_secs[2];
static std::atomic<bool>   g_drift_reset[2];
static std::atomic<bool>   g_reset[2];

static pcap_t      *g_ph = NULL;
static unsigned char g_dl_mac[6];

static bool  g_persist    = true;
static bool  g_autofit    = true;
static bool  g_cursors    = false;
static float g_afterglow  = 3.0f;
static float g_blank_secs = 3.0f;

static double g_cx[2][2] = { { 4.0, 8.0 }, { 4.0, 8.0 } };
static double g_cy[2][2] = { { -0.1, 0.1 }, { -0.1, 0.1 } };

/* ================================================ capture-thread state only */

typedef struct {
    std::vector<int16_t> mn, mx;
    std::vector<int32_t> si, sq;
    std::vector<uint8_t> seen;

    std::vector<float> lo, hi;      /* true cell order */
    std::vector<float> rlo, rhi;    /* rotated         */
    std::vector<float> plo, phi;
    std::vector<float> span, ref;

    int    have_ref;
    int    last_shift;
    int    locked;

    double pos, pos0;               /* unwrapped shift, cells */
    int    track_init;
    uint64_t t0;

    uint32_t last_cell;
    int      started;
    int      idx;
} dir_t;

static dir_t g_dl, g_ul;

static void dir_init(dir_t *d, int idx)
{
    int N = C.cells;
    d->mn.assign(N, 0); d->mx.assign(N, 0);
    d->si.assign(N, 0); d->sq.assign(N, 0);
    d->seen.assign(N, 0);
    d->lo.assign(N, 0.f);  d->hi.assign(N, 0.f);
    d->rlo.assign(N, 0.f); d->rhi.assign(N, 0.f);
    d->plo.assign(N, 0.f); d->phi.assign(N, 0.f);
    d->span.assign(N, 0.f); d->ref.assign(N, 0.f);
    d->have_ref = 0; d->last_shift = 0; d->locked = 0;
    d->pos = d->pos0 = 0.0; d->track_init = 0; d->t0 = 0;
    d->last_cell = 0; d->started = 0; d->idx = idx;
}

static void env_init(env_t *E)
{
    int N = C.cells;
    E->lo.assign(N, 0.f);  E->hi.assign(N, 0.f);
    E->plo.assign(N, 0.f); E->phi.assign(N, 0.f);
    E->dc_i = E->dc_q = 0.f;
    E->peak_cell = -1; E->peak_span = 0.f; E->peak_abs = 0.f;
    E->b0 = E->b1 = -1; E->nburst = 0;
    E->shift = 0; E->corr = 0.0; E->locked = 0;
}

/* Normalised circular cross-correlation. Returns the shift that best aligns
   x onto ref, and writes the correlation there. window <= 0 means search
   every shift. No assumption is made about the shape of either signal - one
   burst, several, or none. */
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
        double r = (acc - (double)N * xm * rm) / denom;
        if (r > best_r) { best_r = r; best_s = ss; }
    }
    *out_r = best_r;
    return best_s;
}

static void finish_frame(dir_t *d)
{
    const int N = C.cells;
    const int k_idx = d->idx;
    const bool clear = g_reset[k_idx].exchange(false);
    const float burst_floor = BURST_FLOOR_LSB / (float)C.full_scale;

    float k = 0.0f;
    if (g_afterglow > 0.01f)
        k = 1.0f - expf(-1.0f / (FRAMES_PER_SEC * g_afterglow));

    uint32_t have = 0;
    int64_t  tot_i = 0, tot_q = 0;
    int      peak_cell = -1;
    float    peak_span = 0.0f, peak_abs = 0.0f;

    for (int c = 0; c < N; c++) {
        have += d->seen[c];

        float a = (float)d->mn[c] / (float)C.full_scale;
        float b = (float)d->mx[c] / (float)C.full_scale;
        d->lo[c] = a; d->hi[c] = b;

        float sp = b - a;
        d->span[c] = sp;
        if (sp > peak_span) { peak_span = sp; peak_cell = c; }
        if (fabsf(a) > peak_abs) peak_abs = fabsf(a);
        if (fabsf(b) > peak_abs) peak_abs = fabsf(b);

        tot_i += d->si[c]; tot_q += d->sq[c];
        d->mn[c] = 0; d->mx[c] = 0; d->si[c] = 0; d->sq[c] = 0;
    }
    std::fill(d->seen.begin(), d->seen.end(), (uint8_t)0);

    if (peak_span < burst_floor) { peak_cell = -1; peak_span = 0.0f; }

    /* burst extent, true cell order */
    int b0 = -1, b1 = -1, nburst = 0;
    if (peak_cell >= 0) {
        float thr = peak_span * BURST_FRAC;
        if (thr < burst_floor) thr = burst_floor;
        for (int c = 0; c < N; c++)
            if (d->span[c] >= thr) { if (b0 < 0) b0 = c; b1 = c; nburst++; }
    }

    /* ---- alignment by correlation, computed whether or not it is applied */
    int    shift = 0;
    double corr  = 0.0;
    int    locked = 0;

    if (g_reacquire[k_idx].exchange(false)) { d->have_ref = 0; d->locked = 0; }

    if (peak_cell >= 0) {
        if (!d->have_ref) {
            d->ref = d->span;
            d->have_ref = 1;
            d->last_shift = 0;
            shift = 0; corr = 1.0; locked = 1;
        } else {
            int win = d->locked ? CORR_TRACK_WIN : 0;    /* 0 = full search */
            shift = best_shift(d->span, d->ref, d->last_shift, win, &corr);
            locked = (corr >= CORR_LOCK);
            if (!locked && win) {                         /* lost it, re-search */
                shift = best_shift(d->span, d->ref, 0, 0, &corr);
                locked = (corr >= CORR_LOCK);
            }
        }
        d->locked = locked;

        if (locked) {
            int delta = shift - d->last_shift;
            if (delta >  N / 2) delta -= N;
            if (delta < -N / 2) delta += N;
            if (!d->track_init) {
                d->track_init = 1;
                d->pos = d->pos0 = 0.0;
                d->t0 = now_us();
            } else {
                d->pos += delta;
            }
            d->last_shift = shift;

            /* adapt the reference slowly, in its own aligned frame */
            for (int c = 0; c < N; c++) {
                int s = c + shift; if (s >= N) s -= N;
                d->ref[c] += (d->span[s] - d->ref[c]) * REF_ALPHA;
            }
        }
    } else {
        d->locked = 0;
    }

    uint64_t now = now_us();
    if (g_drift_reset[k_idx].exchange(false)) { d->pos0 = d->pos; d->t0 = now; }
    if (d->track_init && now > d->t0) {
        double secs = (double)(now - d->t0) / 1e6;
        /* one cell lasts cell_us microseconds, so cells per second is ppm */
        g_ppm[k_idx].store((d->pos - d->pos0) * C.cell_us / secs);
        g_drift_secs[k_idx].store(secs);
    }

    const int disp_shift = (g_align.load() && d->locked) ? shift : 0;

    const std::vector<float> *slo = &d->lo, *shi = &d->hi;
    if (disp_shift) {
        for (int c = 0; c < N; c++) {
            int s = c + disp_shift; if (s >= N) s -= N;
            d->rlo[c] = d->lo[s];
            d->rhi[c] = d->hi[s];
        }
        slo = &d->rlo; shi = &d->rhi;
    }

    /* persistence updated AFTER the rotation, so an aligned display keeps a
       sharp band instead of smearing over every position the burst visited */
    for (int c = 0; c < N; c++) {
        float a = (*slo)[c], b = (*shi)[c];
        if (clear) { d->plo[c] = a; d->phi[c] = b; }
        else {
            d->phi[c] = (b > d->phi[c]) ? b : d->phi[c] + (b - d->phi[c]) * k;
            d->plo[c] = (a < d->plo[c]) ? a : d->plo[c] + (a - d->plo[c]) * k;
        }
    }

    const double n = (double)N * (double)C.spp;
    {
        env_t *E = &g_env[k_idx];
        std::lock_guard<std::mutex> lk(g_env_mtx[k_idx]);
        E->lo = *slo; E->hi = *shi;
        E->plo = d->plo; E->phi = d->phi;
        E->dc_i = (float)((double)tot_i / n);
        E->dc_q = (float)((double)tot_q / n);
        E->peak_cell = peak_cell; E->peak_span = peak_span; E->peak_abs = peak_abs;
        E->b0 = b0; E->b1 = b1; E->nburst = nburst;
        E->shift = disp_shift; E->corr = corr; E->locked = d->locked;
    }

    g_cellcount[k_idx].store(have);
    g_last_us[k_idx].store(now);
}

/* hot path: one pass over the samples, integer compares only */
static void on_packet(unsigned char *user, const struct pcap_pkthdr *h,
                      const unsigned char *bytes)
{
    (void)user;

    const int need = C.hdr_off + C.iq_off + C.spp * 4;
    if ((int)h->caplen < need) { g_trunc++; return; }

    const unsigned char *b = bytes + C.hdr_off;
    if (C.ver >= 0 && ((b[0] >> 4) & 0x0F) != C.ver)      { g_bad++; return; }
    if (C.msgtype >= 0 && b[1] != (unsigned char)C.msgtype) { g_bad++; return; }

    uint16_t v;
    memcpy(&v, b + 6, 2);
    int seq = (int)ntohs(v);
    if (seq < C.seq_base || seq >= C.seq_base + C.cells) { g_bad++; return; }

    const uint32_t cell = (uint32_t)(seq - C.seq_base);

    int is_dl = (memcmp(bytes + 6, g_dl_mac, 6) == 0);
    dir_t *d  = is_dl ? &g_dl : &g_ul;

    /* a real frame wrap is a large backward jump; a small one is a
       reordering and must not cut the frame in two */
    if (d->started && cell < d->last_cell &&
        d->last_cell - cell > (uint32_t)(C.cells / 2)) finish_frame(d);
    d->started   = 1;
    d->last_cell = cell;

    const int16_t *iq = (const int16_t *)(b + C.iq_off);
    const int      ns = C.spp;

    int16_t mn = 0, mx = 0;

    if (g_measure_dc.load(std::memory_order_relaxed)) {
        /* Q is in the same cache line as I, so this costs arithmetic rather
           than memory traffic */
        int32_t si = 0, sq = 0;
        for (int i = 0; i < ns; i++) {
            int16_t I = iq[2 * i], Q = iq[2 * i + 1];
            if (I < mn) mn = I;
            if (I > mx) mx = I;
            si += I; sq += Q;
        }
        d->si[cell] = si; d->sq[cell] = sq;
    } else {
        for (int i = 0; i < ns; i++) {
            int16_t I = iq[2 * i];
            if (I < mn) mn = I;
            if (I > mx) mx = I;
        }
        d->si[cell] = 0; d->sq[cell] = 0;
    }

    d->mn[cell] = mn; d->mx[cell] = mx; d->seen[cell] = 1;
}

static void stats_thread()
{
    struct pcap_stat st;
    uint32_t pd = 0, pi = 0;
    while (g_running.load()) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        if (g_ph && pcap_stats(g_ph, &st) == 0) {
            g_drop.store(st.ps_drop - pd);
            g_ifdrop.store(st.ps_ifdrop - pi);
            pd = st.ps_drop; pi = st.ps_ifdrop;
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
static std::vector<std::string> g_tick_str;
static std::vector<const char *> g_tick_lbl;

static double g_span_hold[2] = { 1e-4, 1e-4 };

static void draw_trace(const char *title, int idx, ImVec4 col, bool show_x,
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
        std::lock_guard<std::mutex> lk(g_env_mtx[idx]);
        const env_t *E = &g_env[idx];
        for (int c = 0; c < N; c++) {
            g_lo[c]  = E->lo[c];  g_hi[c]  = E->hi[c];
            g_plo[c] = E->plo[c]; g_phi[c] = E->phi[c];
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

    if (ImPlot::BeginPlot(title, ImVec2(-1, -1), ImPlotFlags_NoLegend)) {
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

static void lane_status(const char *name, int idx, uint64_t now, bool blank)
{
    uint64_t last = g_last_us[idx].load();
    if (last == 0) {
        ImGui::TextColored(ImVec4(0.6f, 0.6f, 0.6f, 1), "  %s  no frame yet", name);
        return;
    }
    uint64_t age = now - last;

    if (blank) {
        ImGui::TextColored(ImVec4(0.6f, 0.6f, 0.6f, 1),
                           "  %s  NO SIGNAL  -- quiet for %.0f s, display cleared",
                           name, age / 1e6);
        return;
    }
    if (age > STALE_US) {
        ImGui::TextColored(ImVec4(1, 0.55f, 0.25f, 1),
                           "  %s  STALE %.1f s  -- last frame, not live",
                           name, age / 1e6);
        return;
    }

    env_t E;
    { std::lock_guard<std::mutex> lk(g_env_mtx[idx]); E = g_env[idx]; }

    char dcbuf[72] = "";
    if (g_measure_dc.load())
        snprintf(dcbuf, sizeof dcbuf, "   DC I=%+.0f Q=%+.0f (%.2f%% FS)",
                 E.dc_i, E.dc_q,
                 100.0 * sqrt((double)E.dc_i * E.dc_i +
                              (double)E.dc_q * E.dc_q) / C.full_scale);

    ImGui::Text("  %s  %u/%d cells   peak %.4f%s",
                name, g_cellcount[idx].load(), C.cells, E.peak_abs, dcbuf);

    if (E.peak_cell < 0) {
        ImGui::TextColored(ImVec4(0.6f, 0.6f, 0.6f, 1),
                           "      no burst above the noise floor");
        return;
    }

    const double w = (double)(E.b1 - E.b0 + 1);
    ImGui::Text("      peak cell %d (slot %.2f)   burst %d..%d = slot %.2f..%.2f"
                "   width %.0f us (%d cells)   duty %.1f%%",
                E.peak_cell, E.peak_cell / (double)C.pps, E.b0, E.b1,
                E.b0 / (double)C.pps, (E.b1 + 1) / (double)C.pps,
                w * C.cell_us, (int)w, 100.0 * E.nburst / (double)C.cells);

    if (!E.locked) {
        ImGui::TextColored(ImVec4(1, 0.55f, 0.25f, 1),
                           "      NO LOCK  (corr %.2f)  -- no repeating pattern "
                           "to align to; drift not measurable", E.corr);
        return;
    }

    const double ppm  = g_ppm[idx].load();
    const double secs = g_drift_secs[idx].load();
    const ImVec4 pc = (secs < 30.0) ? ImVec4(0.65f, 0.65f, 0.65f, 1)
                                    : ImVec4(1.0f, 0.8f, 0.3f, 1);
    ImGui::TextColored(pc,
        "      lock corr %.2f  shift %d cells   drift %+.3f ppm over %.0f s%s",
        E.corr, E.shift, ppm, secs,
        (secs < 30.0) ? "  (too short to trust)" : "");
}

static void cursor_readout(const char *name, int idx)
{
    const double x0 = g_cx[idx][0], x1 = g_cx[idx][1];
    const double y0 = g_cy[idx][0], y1 = g_cy[idx][1];
    const double dx = fabs(x1 - x0), dy = fabs(y1 - y0);
    const double dt_us = dx * C.slot_us;

    char rate[48] = "";
    if (dt_us > 1e-9) {
        double hz = 1e6 / dt_us;
        if (hz >= 1000.0) snprintf(rate, sizeof rate, "   1/dt = %.3f kHz", hz / 1000.0);
        else              snprintf(rate, sizeof rate, "   1/dt = %.1f Hz", hz);
    }

    ImGui::Text("  %s cursors   x %.3f .. %.3f slot   dx %.3f slot = %.1f us "
                "= %.0f samples = %.1f packets%s",
                name, x0, x1, dx, dt_us,
                dx * (double)C.pps * C.spp, dx * (double)C.pps, rate);
    ImGui::Text("              y %+.5f .. %+.5f   dy %.5f = %.0f counts of FS",
                y0, y1, dy, dy * C.full_scale);
}

int main(int argc, char **argv)
{
    cfg_defaults();

    if (argc < 3) {
        fprintf(stderr, USAGE, argv[0], argv[0], argv[0]);
        return 1;
    }
    const char *iface = argv[1];
    const char *macs  = argv[2];

    for (int a = 3; a < argc; a++) {
        std::string k = argv[a];
        if (k == "-c") {
            if (a + 1 >= argc) { std::cerr << "-c needs a file\n"; return 1; }
            if (cfg_file(argv[++a])) return 1;
            continue;
        }
        if (k.size() > 2 && k[0] == '-' && k[1] == '-') {
            if (a + 1 >= argc) { std::cerr << k << " needs a value\n"; return 1; }
            if (cfg_set(k.substr(2), argv[++a])) return 1;
            continue;
        }
        std::cerr << "unexpected argument: " << k << "\n";
        fprintf(stderr, USAGE, argv[0], argv[0], argv[0]);
        return 1;
    }

    if (cfg_derive()) return 1;

    unsigned int m[6];
    if (sscanf(macs, "%x:%x:%x:%x:%x:%x",
               &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]) != 6) {
        std::cerr << "bad MAC: " << macs << "\n"; return 1;
    }
    for (int i = 0; i < 6; i++) g_dl_mac[i] = (unsigned char)m[i];

    std::cerr << "link: " << C.rate_hz / 1e6 << " Msps, mu=" << C.mu
              << ", " << C.spp << " samples/packet\n"
              << "  -> " << C.sps << " samples/slot, " << C.pps
              << " packets/slot, " << C.slots << " slots/frame, "
              << C.cells << " packets/frame\n"
              << "  -> cell " << C.cell_us << " us, slot " << C.slot_us
              << " us, " << (int)(C.cells * 100) << " packets/s per lane\n";

    dir_init(&g_dl, 1);
    dir_init(&g_ul, 0);
    env_init(&g_env[0]);
    env_init(&g_env[1]);

    const int N = C.cells;
    g_xs.resize(N); g_lo.resize(N); g_hi.resize(N);
    g_plo.resize(N); g_phi.resize(N); g_mid.resize(N);
    for (int c = 0; c < N; c++) g_xs[c] = (double)c / (double)C.pps;

    g_grid.resize(C.slots + 1);
    for (int s = 0; s <= C.slots; s++) g_grid[s] = s;

    g_tick_pos.resize(C.slots);
    g_tick_str.resize(C.slots);
    g_tick_lbl.resize(C.slots);
    for (int s = 0; s < C.slots; s++) {
        g_tick_pos[s] = s + 0.5;
        g_tick_str[s] = std::to_string(s);
        g_tick_lbl[s] = g_tick_str[s].c_str();
    }

    glfwSetErrorCallback(glfwErrorCallback);
    if (!glfwInit()) { std::cerr << "glfwInit failed\n"; return 1; }

    glfwDefaultWindowHints();
    GLFWwindow *window = glfwCreateWindow(1500, 940,
                                          "Split 8 fronthaul scope", nullptr, nullptr);
    if (!window) { std::cerr << "no window - is DISPLAY set?\n"; glfwTerminate(); return 1; }

    glfwMakeContextCurrent(window);
    glfwSwapInterval(1);
    if (glewInit() != GLEW_OK) { std::cerr << "glewInit failed\n"; return 1; }

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImPlot::CreateContext();
    ImGui::StyleColorsDark();
    ImGui::GetIO().FontGlobalScale = 1.25f;

    ImGui_ImplGlfw_InitForOpenGL(window, true);
    ImGui_ImplOpenGL3_Init("#version 130");

    std::thread cap(capture_thread, iface);
    std::thread sta(stats_thread);

    const ImVec4 COL_DL(1.00f, 0.85f, 0.10f, 1.0f);
    const ImVec4 COL_UL(0.20f, 0.95f, 0.35f, 1.0f);

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

        const uint64_t now  = now_us();
        const uint32_t drop = g_drop.load(), ifdrop = g_ifdrop.load();
        const uint64_t blank_us = (uint64_t)(g_blank_secs * 1e6);

        bool stale[2], blank[2];
        for (int i = 0; i < 2; i++) {
            uint64_t last = g_last_us[i].load();
            uint64_t age  = last ? now - last : 0;
            stale[i] = last && age > STALE_US;
            blank[i] = last && age > blank_us;
        }

        ImGui::Text("%s   DL src %s   |   %.2f Msps  mu=%d  %d samples/pkt  "
                    "%d pkt/slot  %d slots  %d cells/frame",
                    iface, macs, C.rate_hz / 1e6, C.mu, C.spp, C.pps,
                    C.slots, C.cells);

        if (drop || ifdrop)
            ImGui::TextColored(ImVec4(1, 0.25f, 0.25f, 1),
                               "LOSSY  drop=+%u ifdrop=+%u   -- trace has holes",
                               drop, ifdrop);
        else
            ImGui::TextColored(ImVec4(0.3f, 1, 0.3f, 1), "clean  drop=0 ifdrop=0");

        if (g_bad.load() || g_trunc.load())
            ImGui::TextColored(ImVec4(1, 0.8f, 0.3f, 1),
                               "rejected: bad=%llu trunc=%llu   "
                               "-- check --seq-base, --version, --msgtype",
                               (unsigned long long)g_bad.load(),
                               (unsigned long long)g_trunc.load());

        lane_status("DL", 1, now, blank[1]);
        lane_status("UL", 0, now, blank[0]);
        if (g_cursors) { cursor_readout("DL", 1); cursor_readout("UL", 0); }

        ImGui::Checkbox("persistence", &g_persist);
        ImGui::SameLine();
        if (ImGui::Button("clear")) { g_reset[0].store(true); g_reset[1].store(true); }
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
        if (ImGui::Button("re-acquire")) {
            g_reacquire[0].store(true); g_reacquire[1].store(true);
        }
        ImGui::SameLine();
        ImGui::Checkbox("cursors", &g_cursors);
        ImGui::SameLine();
        bool dc = g_measure_dc.load();
        if (ImGui::Checkbox("measure DC", &dc)) g_measure_dc.store(dc);
        ImGui::SameLine();
        if (ImGui::Button("reset drift")) {
            g_drift_reset[0].store(true); g_drift_reset[1].store(true);
        }

        if (ImPlot::BeginSubplots("##stack", 2, 1, ImVec2(-1, -1),
                                  ImPlotSubplotFlags_LinkCols)) {
            draw_trace("DL   gNB -> UE", 1, COL_DL, false, stale[1], blank[1]);
            draw_trace("UL   UE -> gNB", 0, COL_UL, true,  stale[0], blank[0]);
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
