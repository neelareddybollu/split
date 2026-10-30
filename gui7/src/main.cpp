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

    /* OFDM geometry, derived. At mu=1 / 122.88 Msps the FFT bin spacing comes
       out at exactly one subcarrier, which is what makes the grid exact:
         4096 bins over 122.88 MHz = 30 kHz = the subcarrier spacing
         352 + 13*288 + 14*4096   = 61440 = one slot, to the sample          */
    int      nfft;           /* FFT size                                     */
    int      cp0, cp1;       /* cyclic prefix, first symbol and the rest     */
    int      nsym;           /* OFDM symbols per slot, always 14             */
    int      nsc;            /* occupied subcarriers = 12 * PRB              */
    int      nprb;
    int      ofdm_ok;        /* geometry closes exactly                      */
    double   fc_hz;          /* carrier, only used to turn Hz into ppm       */
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
"  --prb <n>         occupied resource blocks (default: from the FFT size)\n"
"  --fc <MHz>        carrier, only used to express offsets in ppm (3750)\n"
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

    /* OFDM: pick the power-of-two FFT that the slot divides into cleanly.
       scs = 15 kHz * 2^mu, so nfft = sample_rate / scs. */
    {
        const double scs  = 15000.0 * (double)(1 << C.mu);
        const double nf   = C.rate_hz / scs;
        C.nsym   = 14;
        C.nfft   = (int)(nf + 0.5);
        C.ofdm_ok = 0;
        if (fabs(nf - C.nfft) < 1e-6 && C.nfft >= 128 &&
            (C.nfft & (C.nfft - 1)) == 0) {
            /* 3GPP normal CP: the long prefix carries the extra samples that
               make the slot close exactly */
            const int rest = C.sps - C.nsym * C.nfft;
            C.cp1 = (int)(C.nfft * 0.0703125 + 0.5);      /* 288 at 4096 */
            C.cp0 = rest - 13 * C.cp1;
            if (C.cp0 > 0 && C.cp0 < C.nfft &&
                C.cp0 + 13 * C.cp1 + C.nsym * C.nfft == C.sps)
                C.ofdm_ok = 1;
        }
        if (C.ofdm_ok) {
            if (C.nprb <= 0) C.nprb = (C.nfft * 9) / 10 / 12;   /* default */
            if (C.nprb * 12 > C.nfft) C.nprb = C.nfft / 12;
            C.nsc = C.nprb * 12;
        } else { C.nprb = 0; C.nsc = 0; }
    }

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
    else if (k == "prb")       C.nprb      = atoi(v.c_str());
    else if (k == "fc")        C.fc_hz     = atof(v.c_str()) * 1e6;
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
    int    peak_cell;        /* -1 when the lane is silent; gates the lock */
    float  peak_span, peak_abs;
    int    shift;
    double corr;
    int    elocked;

    std::atomic<uint32_t> cells;
    std::atomic<uint64_t> pkts, pps, last_us;
    std::atomic<bool>     reset, reacquire, drift_reset;
    std::atomic<double>   ppm, drift_secs;

    /* sequence audit and arrival timing - written in the hot path */
    std::atomic<uint64_t> n_ooo, n_dup;
    struct timeval        arr_t0;
    int                   arr_valid;
    std::atomic<double>   jit_lo, jit_hi;

    /* render thread only - a stored frame to compare the live one against */
    std::vector<double> ref_lo, ref_hi;
    int                 has_ref;
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

/* RUN/STOP. Stopping discards packets at the top of on_packet rather than
   tearing down the capture: pcap_loop keeps draining the socket, so the
   kernel ring never overflows and RUN resumes on live data instead of a
   backlog. Nothing reaches a lane, so every number and every trace freezes
   by itself - no snapshot machinery needed. */
static std::atomic<bool>     g_acquire(true);
static std::atomic<uint64_t> g_stop_us(0);

/* ---- Stop when: arm a condition, walk away, come back to a frozen screen
   showing the moment it fired. With no condition ticked it stops on the
   very next frame, which is a scope's SINGLE. ---- */
static std::atomic<bool>  g_armed(false);
static std::atomic<bool>  g_trg_cells(false);
static std::atomic<int>   g_trg_cells_n(640);
static std::atomic<bool>  g_trg_slot(false);
static std::atomic<int>   g_trg_slot_n(8);
static std::atomic<bool>  g_trg_silent(false);
static std::atomic<bool>  g_trg_drop(false);
static std::mutex         g_trg_mtx;
static char               g_trg_reason[160] = "";

static void trigger_fire(const char *why, uint64_t now)
{
    {
        std::lock_guard<std::mutex> g(g_trg_mtx);
        snprintf(g_trg_reason, sizeof g_trg_reason, "%s", why);
    }
    g_armed.store(false);
    g_stop_us.store(now);
    g_acquire.store(false);
}

static pcap_t *g_ph = NULL;

/* one control, three states, instead of a checkbox and a slider that both
   governed the same thing */
enum { AG_OFF = 0, AG_FADE = 1, AG_HOLD = 2 };
static int   g_ag_mode    = AG_FADE;
static bool  g_persist    = true;          /* derived from g_ag_mode */
static bool  g_autofit    = true;
static bool  g_cursors    = false;
static float g_afterglow  = 3.0f;
static float g_blank_secs = 3.0f;

/* Compare: freeze a known-good frame and hold the live one against it */
enum { CMP_OFF = 0, CMP_OVERLAY = 1, CMP_DIFF = 2 };
static int  g_cmp_mode = CMP_OFF;
static bool g_save_ref = false;

/* Zoom: look at a slot range instead of the whole frame */
static bool  g_zoom    = false;
static float g_zoom_lo = 0.0f, g_zoom_hi = 2.0f;

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
    L->shift = 0; L->corr = 0.0; L->elocked = 0;
    L->cells.store(0); L->pkts.store(0); L->pps.store(0); L->last_us.store(0);
    L->reset.store(false); L->reacquire.store(false); L->drift_reset.store(false);
    L->ppm.store(0.0); L->drift_secs.store(0.0);
    L->ref_lo.assign(N, 0.0); L->ref_hi.assign(N, 0.0); L->has_ref = 0;
    L->n_ooo.store(0); L->n_dup.store(0); L->arr_valid = 0;
    L->jit_lo.store(0.0); L->jit_hi.store(0.0);
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

/* ==================================================================== *
 *  One-shot slot analysis: cyclic-prefix correlation and resource grid
 *
 *  This is the step from "there is energy in slot 10" to "24 resource
 *  blocks in symbol 0". It runs on demand, never per frame, so the FFT
 *  cost never touches the capture rate: arm it, the hot path copies one
 *  slot's raw IQ aside as it goes past, and the analysis runs once.
 *
 *  CYCLIC-PREFIX CORRELATION is the cheaper and, for timing questions,
 *  the more useful half. Each OFDM symbol begins with a copy of its own
 *  tail, so correlating the prefix against the body a symbol-length
 *  later gives two things at once:
 *
 *      |r|      how well the two match -> confirms sample alignment,
 *               FFT size and numerology all at once
 *      arg(r)   carrier frequency offset, because a frequency error
 *               rotates the signal by 2*pi*df*Tu over that interval
 *
 *                 df = -arg(r) / (2*pi*Tu),   Tu = nfft / sample_rate
 *
 *  At 4096 / 122.88 Msps, Tu is 33.33 us, so a full 2*pi of phase is
 *  30 kHz and the measurement is unambiguous to about +/-15 kHz. This
 *  measures the waveform itself - it needs no pattern to lock onto and
 *  makes no assumption about what seq_id means.
 * ==================================================================== */

static std::atomic<bool>    g_an_arm(false);
static std::atomic<bool>    g_an_ready(false);
static std::atomic<int>     g_an_lane(0), g_an_slot(0);
static std::mutex           g_an_mtx;
static std::vector<int16_t> g_an_raw;      /* 2 * samples_per_slot, I/Q */
static std::vector<uint8_t> g_an_got;

/* results, render thread only */
static std::vector<float> g_an_grid;       /* nsym * nprb, dBFS   */
static std::vector<float> g_an_cpmag;      /* nsym, 0..1          */
static std::vector<float> g_an_cpHz;       /* nsym, Hz            */
static float g_an_Hz = 0.0f, g_an_ppm = 0.0f, g_an_conf = 0.0f;
static float g_an_lo_db = -90.0f, g_an_hi_db = -20.0f;
static int   g_an_have = 0, g_an_shown_slot = 0;
static char  g_an_src[48] = "";

static void fft_tables(int n, std::vector<float> &wr, std::vector<float> &wi)
{
    wr.resize(n / 2); wi.resize(n / 2);
    for (int i = 0; i < n / 2; i++) {
        const double a = -2.0 * M_PI * (double)i / (double)n;
        wr[i] = (float)cos(a); wi[i] = (float)sin(a);
    }
}

/* iterative radix-2, in place */
static void fft_run(float *re, float *im, int N,
                    const float *wr, const float *wi)
{
    for (int i = 1, j = 0; i < N; i++) {
        int bit = N >> 1;
        for (; j & bit; bit >>= 1) j ^= bit;
        j ^= bit;
        if (i < j) { float t;
            t = re[i]; re[i] = re[j]; re[j] = t;
            t = im[i]; im[i] = im[j]; im[j] = t; }
    }
    for (int len = 2; len <= N; len <<= 1) {
        const int half = len >> 1, step = N / len;
        for (int i = 0; i < N; i += len)
            for (int k = 0; k < half; k++) {
                const float w0 = wr[k * step], w1 = wi[k * step];
                const float xr = re[i + k + half], xi = im[i + k + half];
                const float vr = xr * w0 - xi * w1;
                const float vi = xr * w1 + xi * w0;
                const float ur = re[i + k], ui = im[i + k];
                re[i + k] = ur + vr;        im[i + k] = ui + vi;
                re[i + k + half] = ur - vr; im[i + k + half] = ui - vi;
            }
    }
}

static void analyse_slot(void)
{
    std::vector<int16_t> raw;
    { std::lock_guard<std::mutex> g(g_an_mtx); raw = g_an_raw; }

    const int N = C.nfft, NS = C.nsym, NP = C.nprb;
    std::vector<float> wr, wi; fft_tables(N, wr, wi);

    g_an_grid.assign((size_t)NS * NP, -140.0f);
    g_an_cpmag.assign(NS, 0.0f);
    g_an_cpHz.assign(NS, 0.0f);

    const double Tu  = (double)N / C.rate_hz;
    const double fs2 = C.full_scale * C.full_scale;

    std::vector<float> re(N), im(N);
    int    off  = 0;
    double fsum = 0.0, wsum = 0.0;

    for (int sy = 0; sy < NS; sy++) {
        const int cp = (sy == 0) ? C.cp0 : C.cp1;

        /* ---- cyclic prefix against the symbol tail, one period later ---- */
        double cr = 0, ci = 0, pa = 0, pb = 0;
        for (int n = 0; n < cp; n++) {
            const double ai = raw[(size_t)(off + n) * 2];
            const double aq = raw[(size_t)(off + n) * 2 + 1];
            const double bi = raw[(size_t)(off + N + n) * 2];
            const double bq = raw[(size_t)(off + N + n) * 2 + 1];
            cr += ai * bi + aq * bq;          /* a * conj(b) */
            ci += aq * bi - ai * bq;
            pa += ai * ai + aq * aq;
            pb += bi * bi + bq * bq;
        }
        const double den = sqrt(pa * pb);
        const double mag = (den > 1e-9) ? sqrt(cr * cr + ci * ci) / den : 0.0;
        const double hz  = (den > 1e-9)
                         ? -atan2(ci, cr) / (2.0 * M_PI * Tu) : 0.0;
        g_an_cpmag[sy] = (float)mag;
        g_an_cpHz[sy]  = (float)hz;
        if (pa > 0.0) { fsum += hz * mag; wsum += mag; }

        /* ---- the symbol body, prefix skipped ---- */
        for (int k = 0; k < N; k++) {
            re[k] = (float)raw[(size_t)(off + cp + k) * 2];
            im[k] = (float)raw[(size_t)(off + cp + k) * 2 + 1];
        }
        fft_run(re.data(), im.data(), N, wr.data(), wi.data());

        for (int pr = 0; pr < NP; pr++) {
            double acc = 0.0;
            for (int t = 0; t < 12; t++) {
                const int sc  = -(NP * 12) / 2 + pr * 12 + t;
                const int bin = ((sc % N) + N) % N;
                acc += (double)re[bin] * re[bin] + (double)im[bin] * im[bin];
            }
            const double pw = acc / (12.0 * (double)N * (double)N * fs2);
            g_an_grid[(size_t)sy * NP + pr] =
                (float)(pw > 1e-14 ? 10.0 * log10(pw) : -140.0);
        }
        off += cp + N;
    }

    g_an_Hz   = (float)(wsum > 1e-9 ? fsum / wsum : 0.0);
    g_an_conf = (float)(wsum / (double)NS);
    g_an_ppm  = (float)(C.fc_hz > 0 ? g_an_Hz / C.fc_hz * 1e6 : 0.0);
    g_an_have = 1;
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
        L->shift = disp_shift; L->corr = corr; L->elocked = L->locked;
    }
    /* ---- Stop when ---- */
    if (g_armed.load() && g_acquire.load()) {
        char why[160];
        const char *fired = NULL;

        if (g_trg_cells.load() && (int)have < g_trg_cells_n.load()) {
            snprintf(why, sizeof why, "%s  %u/%d cells (below %d)",
                     L->title, have, N, g_trg_cells_n.load());
            fired = why;
        } else if (g_trg_slot.load()) {
            const int sl = g_trg_slot_n.load();
            const int c0 = sl * C.pps, c1 = c0 + C.pps;
            if (c0 >= 0 && c1 <= N) {
                float mx = 0.0f;
                for (int c = c0; c < c1; c++)
                    if (L->span[c] > mx) mx = L->span[c];
                if (mx > burst_floor * 4.0f) {
                    snprintf(why, sizeof why,
                             "%s  energy in slot %d (%.4f)", L->title, sl, mx);
                    fired = why;
                }
            }
        } else if (!g_trg_cells.load() && !g_trg_silent.load() &&
                   !g_trg_drop.load()) {
            snprintf(why, sizeof why, "%s  single frame captured", L->title);
            fired = why;                      /* no condition = SINGLE */
        }
        if (fired) trigger_fire(fired, now);
    }

    L->cells.store(have);
    L->last_us.store(now);
}

/* hot path: one pass over the samples, integer compares only */
static void on_packet(unsigned char *user, const struct pcap_pkthdr *h,
                      const unsigned char *bytes)
{
    (void)user;

    if (!g_acquire.load(std::memory_order_relaxed)) return;   /* STOPPED */

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

    /* sequence audit: a duplicate is a cell written twice in one frame, an
       out-of-order is a backward step too small to be a frame wrap */
    if (L->seen[cell]) L->n_dup.fetch_add(1, std::memory_order_relaxed);
    if (L->started && cell < L->last_cell &&
        L->last_cell - cell <= (uint32_t)(C.cells / 2))
        L->n_ooo.fetch_add(1, std::memory_order_relaxed);

    /* arrival time against the time seq_id implies - the tool measured
       position and never time, which is the blind spot VALIDATION.md names */
    if (cell == 0) {
        L->arr_t0 = h->ts; L->arr_valid = 1;
        L->jit_lo.store(0.0); L->jit_hi.store(0.0);
    } else if (L->arr_valid) {
        const double us = (double)(h->ts.tv_sec  - L->arr_t0.tv_sec) * 1e6
                        + (double)(h->ts.tv_usec - L->arr_t0.tv_usec);
        const double err = us - (double)cell * C.cell_us;
        if (err < L->jit_lo.load(std::memory_order_relaxed))
            L->jit_lo.store(err, std::memory_order_relaxed);
        if (err > L->jit_hi.load(std::memory_order_relaxed))
            L->jit_hi.store(err, std::memory_order_relaxed);
    }

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

    /* one-shot slot grab: only while armed, only the chosen lane and slot,
       so 32 of every 640 packets are touched and then it disarms itself */
    if (g_an_arm.load(std::memory_order_relaxed) && C.ofdm_ok &&
        L == &g_lane[g_an_lane.load(std::memory_order_relaxed)] &&
        (int)(cell / (uint32_t)C.pps) == g_an_slot.load(std::memory_order_relaxed)) {
        const int k = (int)(cell % (uint32_t)C.pps);
        std::lock_guard<std::mutex> g(g_an_mtx);
        memcpy(&g_an_raw[(size_t)k * C.spp * 2], iq, (size_t)C.spp * 4);
        g_an_got[k] = 1;
        int n = 0;
        for (int i = 0; i < C.pps; i++) n += g_an_got[i];
        if (n == C.pps) { g_an_arm.store(false); g_an_ready.store(true); }
    }
}

static void stats_thread()
{
    struct pcap_stat st;
    uint32_t pd = 0, pi = 0;
    uint64_t prev[MAX_LANES] = { 0 };
    while (g_running.load()) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        if (!g_acquire.load()) continue;        /* hold drop/ifdrop/pkt-s */
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

    /* Compare: snapshot the live frame, or hold it against the stored one */
    if (g_save_ref && !blank) {
        L->ref_lo.assign(g_lo.begin(), g_lo.begin() + N);
        L->ref_hi.assign(g_hi.begin(), g_hi.begin() + N);
        L->has_ref = 1;
    }
    if (g_cmp_mode == CMP_DIFF && L->has_ref)
        for (int c = 0; c < N; c++) {
            g_lo[c] -= L->ref_lo[c];
            g_hi[c] -= L->ref_hi[c];
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
        ImPlot::SetupAxisLimits(ImAxis_X1,
                                g_zoom ? g_zoom_lo : 0.0,
                                g_zoom ? g_zoom_hi : (double)C.slots,
                                ImPlotCond_Always);
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

            /* the stored frame, drawn over the live one */
            if (g_cmp_mode == CMP_OVERLAY && L->has_ref) {
                const ImVec4 rc(0.85f, 0.85f, 0.95f, 0.9f);
                ImPlot::SetNextLineStyle(rc, 1.2f);
                ImPlot::PlotLine("##reflo", g_xs.data(), L->ref_lo.data(), N);
                ImPlot::SetNextLineStyle(rc, 1.2f);
                ImPlot::PlotLine("##refhi", g_xs.data(), L->ref_hi.data(), N);
            }
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

/* One line per lane, always exactly one. Lines appearing and disappearing
   changed the header height frame to frame, and since the plots fill what
   is left, the whole display jumped. */
static void lane_status(lane_t *L, ImVec4 col, uint64_t now, bool blank)
{
    const uint64_t last = L->last_us.load();
    const uint64_t rate = L->pps.load();

    if (last == 0) {
        /* receiving but never assembling looked identical to silent, because
           this branch used to return before printing the packet rate */
        ImGui::TextColored(ImVec4(0.65f, 0.65f, 0.65f, 1),
                           "  %-26s %6llu pkt/s   no frame assembled",
                           L->title, (unsigned long long)rate);
        return;
    }
    const uint64_t age = now - last;

    if (blank) {
        ImGui::TextColored(ImVec4(0.6f, 0.6f, 0.6f, 1),
                           "  %-26s NO SIGNAL  -- quiet for %.0f s",
                           L->title, age / 1e6);
        return;
    }
    if (age > STALE_US) {
        ImGui::TextColored(ImVec4(1, 0.55f, 0.25f, 1),
                           "  %-26s STALE %.1f s  -- last frame, not live",
                           L->title, age / 1e6);
        return;
    }

    float dci, dcq, pabs;
    int   pc;
    {
        std::lock_guard<std::mutex> g(L->mtx);
        dci = L->dc_i; dcq = L->dc_q; pabs = L->peak_abs; pc = L->peak_cell;
    }

    char dcbuf[48] = "";
    if (g_measure_dc.load())
        snprintf(dcbuf, sizeof dcbuf, "   DC I=%+.0f Q=%+.0f", dci, dcq);

    ImGui::TextColored(col, "  %-26s %3u/%d cells  %6llu pkt/s  peak %.4f%s%s",
                       L->title, L->cells.load(), C.cells,
                       (unsigned long long)rate, pabs,
                       (pc < 0) ? "   silent" : "", dcbuf);
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

    if (C.ofdm_ok) {
        g_an_raw.assign((size_t)C.sps * 2, 0);
        g_an_got.assign(C.pps, 0);
    }

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

    if (C.ofdm_ok)
        std::cerr << "ofdm: " << C.nfft << "-point FFT, cp " << C.cp0 << "/"
                  << C.cp1 << ", " << C.nsym << " symbols, " << C.nprb
                  << " PRB, bin = subcarrier = "
                  << (C.rate_hz / C.nfft / 1000.0) << " kHz\n";
    else
        std::cerr << "ofdm: geometry does not close for this rate and mu - "
                     "the Analyse tab is disabled\n";

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

        if (g_an_ready.exchange(false)) analyse_slot();

        const int      lanes = g_nlanes.load(std::memory_order_acquire);
        const uint64_t now   = now_us();
        const uint32_t drop  = g_drop.load(), ifdrop = g_ifdrop.load();
        const uint64_t blank_us = (uint64_t)(g_blank_secs * 1e6);

        bool stale[MAX_LANES] = { false }, blank[MAX_LANES] = { false };
        uint64_t total_pps = 0;
        for (int i = 0; i < lanes; i++) {
            const uint64_t last = g_lane[i].last_us.load();
            const uint64_t age  = last ? now - last : 0;
            /* with acquisition stopped last_us stops advancing, so both of
               these would fire and wipe the screen a few seconds after you
               pressed STOP - which is exactly what must not happen */
            stale[i] = g_acquire.load() && last && age > STALE_US;
            blank[i] = g_acquire.load() && last && age > blank_us;

            if (g_armed.load() && g_acquire.load() &&
                g_trg_silent.load() && stale[i]) {
                char why[160];
                snprintf(why, sizeof why, "%s went silent",
                         g_lane[i].title);
                trigger_fire(why, now);
            }
            total_pps += g_lane[i].pps.load();
        }
        const double gbps = (double)total_pps *
                            (double)(C.hdr_off + C.iq_off + C.spp * 4) * 8.0 / 1e9;

        if (g_armed.load() && g_acquire.load() && g_trg_drop.load() &&
            (drop || ifdrop)) {
            char why[160];
            snprintf(why, sizeof why, "capture lost packets: drop=%u ifdrop=%u",
                     drop, ifdrop);
            trigger_fire(why, now);
        }

        const bool  running = g_acquire.load();
        const float winw    = ImGui::GetWindowWidth();

        ImGui::BeginGroup();      /* ---- left column: status ---- */

        ImGui::Text("%s   %d sender%s   %.2f Msps  mu=%d",
                    iface, lanes, lanes == 1 ? "" : "s", C.rate_hz / 1e6, C.mu);

        /* drop and ifdrop are blind to loss inside the switch. If the senders'
           combined rate approaches the mirror port's line rate, cells can sit
           below full on a capture that calls itself clean - which is what the
           Gbit/s figure is here to let you notice. */
        char badbuf[64] = "";
        if (g_bad.load() || g_trunc.load())
            snprintf(badbuf, sizeof badbuf, "   bad=%llu trunc=%llu",
                     (unsigned long long)g_bad.load(),
                     (unsigned long long)g_trunc.load());

        char reason[160];
        { std::lock_guard<std::mutex> g(g_trg_mtx);
          snprintf(reason, sizeof reason, "%s", g_trg_reason); }

        if (!running && reason[0])
            ImGui::TextColored(ImVec4(1, 0.55f, 0.25f, 1),
                               "STOPPED %.0f s ago  --  %s",
                               (now - g_stop_us.load()) / 1e6, reason);
        else if (!running)
            ImGui::TextColored(ImVec4(1, 0.7f, 0.2f, 1),
                               "STOPPED  -- frozen %.0f s ago, not live",
                               (now - g_stop_us.load()) / 1e6);
        else if (drop || ifdrop)
            ImGui::TextColored(ImVec4(1, 0.25f, 0.25f, 1),
                               "LOSSY  drop=+%u ifdrop=+%u   %llu pkt/s   "
                               "%.2f Gbit/s%s", drop, ifdrop,
                               (unsigned long long)total_pps, gbps, badbuf);
        else
            ImGui::TextColored(ImVec4(0.3f, 1, 0.3f, 1),
                               "clean  drop=0 ifdrop=0   %llu pkt/s   "
                               "%.2f Gbit/s%s",
                               (unsigned long long)total_pps, gbps, badbuf);

        for (int i = 0; i < lanes; i++)
            lane_status(&g_lane[i], COL[i % MAX_LANES], now, blank[i]);

        ImGui::EndGroup();

        /* ---- right: acquisition, on its own, away from everything else ---- */
        ImGui::SameLine(winw - 186.0f);
        ImGui::BeginGroup();
        {
            const ImVec4 red  (0.78f, 0.17f, 0.17f, 1.0f);
            const ImVec4 redh (0.90f, 0.26f, 0.26f, 1.0f);
            const ImVec4 grn  (0.13f, 0.60f, 0.24f, 1.0f);
            const ImVec4 grnh (0.20f, 0.72f, 0.33f, 1.0f);
            ImGui::PushStyleColor(ImGuiCol_Button,        running ? red  : grn);
            ImGui::PushStyleColor(ImGuiCol_ButtonHovered, running ? redh : grnh);
            ImGui::PushStyleColor(ImGuiCol_ButtonActive,  running ? redh : grnh);
            if (ImGui::Button(running ? "STOP" : "RUN", ImVec2(160, 48))) {
                g_acquire.store(!running);
                g_armed.store(false);
                if (running) g_stop_us.store(now);
            }
            ImGui::PopStyleColor(3);

            /* arm and go: resume, then stop on the next frame */
            if (ImGui::Button("Single", ImVec2(160, 26))) {
                { std::lock_guard<std::mutex> g(g_trg_mtx); g_trg_reason[0] = 0; }
                g_trg_cells.store(false);  g_trg_slot.store(false);
                g_trg_silent.store(false); g_trg_drop.store(false);
                g_armed.store(true);
                g_acquire.store(true);
            }
            if (g_armed.load())
                ImGui::TextColored(ImVec4(1, 0.8f, 0.3f, 1), " ARMED");
        }
        ImGui::EndGroup();

        const uint64_t ovf = g_overflow.load();
        if (ovf)
            ImGui::TextColored(ImVec4(1, 0.8f, 0.3f, 1),
                               "  more than %d senders -- %llu packets ignored "
                               "rather than folded into another lane",
                               MAX_LANES, (unsigned long long)ovf);

        if (g_cursors)
            for (int i = 0; i < lanes; i++) cursor_readout(&g_lane[i], i);

        ImGui::Separator();

        /* Tabs, not columns. Positioning the second group at a percentage of
           the window width meant it collided with the first whenever the
           first grew - tabs cannot overlap, and only the controls you are
           using are on screen. */
        if (ImGui::BeginTabBar("##tabs")) {

            if (ImGui::BeginTabItem("View")) {
                ImGui::SetNextItemWidth(130);
                ImGui::Combo("Afterglow", &g_ag_mode, "Off\0Fade\0Hold\0");
                g_persist = (g_ag_mode != AG_OFF);
                if (g_ag_mode == AG_FADE) {
                    ImGui::SameLine();
                    ImGui::SetNextItemWidth(150);
                    ImGui::SliderFloat("##fade", &g_afterglow, 0.2f, 20.0f, "%.1f s");
                } else if (g_ag_mode == AG_HOLD) {
                    g_afterglow = 0.0f;       /* never decays */
                }
                ImGui::SameLine();
                if (ImGui::Button("Clear trace"))
                    for (int i = 0; i < lanes; i++) g_lane[i].reset.store(true);
                ImGui::SameLine();
                ImGui::Checkbox("Auto scale", &g_autofit);

                ImGui::Checkbox("Zoom", &g_zoom);
                ImGui::SameLine();
                ImGui::SetNextItemWidth(300);
                ImGui::SliderFloat2("slots", &g_zoom_lo, 0.0f, (float)C.slots,
                                    "%.2f");
                if (g_zoom_hi <= g_zoom_lo) g_zoom_hi = g_zoom_lo + 0.25f;
                ImGui::SameLine();
                ImGui::SetNextItemWidth(150);
                ImGui::SliderFloat("Hide silent after", &g_blank_secs,
                                   1.0f, 30.0f, "%.0f s");
                ImGui::EndTabItem();
            }

            if (ImGui::BeginTabItem("Measure")) {
                ImGui::Checkbox("Cursors", &g_cursors);
                ImGui::SameLine();
                bool dc = g_measure_dc.load();
                if (ImGui::Checkbox("DC offset", &dc)) g_measure_dc.store(dc);
                ImGui::SameLine();
                bool al = g_align.load();
                if (ImGui::Checkbox("Lock to signal", &al)) g_align.store(al);
                ImGui::SameLine();
                /* re-locking clears persistence too - see finish_frame */
                if (ImGui::Button("Re-lock"))
                    for (int i = 0; i < lanes; i++) g_lane[i].reacquire.store(true);
                ImGui::EndTabItem();
            }

            if (ImGui::BeginTabItem("Compare")) {
                g_save_ref = ImGui::Button("Save reference");
                ImGui::SameLine();
                ImGui::SetNextItemWidth(170);
                ImGui::Combo("##cmp", &g_cmp_mode,
                             "Off\0Overlay\0Difference\0");
                ImGui::SameLine();
                int nref = 0;
                for (int i = 0; i < lanes; i++) nref += g_lane[i].has_ref;
                if (nref)
                    ImGui::TextColored(ImVec4(0.6f, 0.75f, 1, 1),
                                       "reference stored for %d lane%s",
                                       nref, nref == 1 ? "" : "s");
                else
                    ImGui::TextColored(ImVec4(0.6f, 0.6f, 0.6f, 1),
                                       "no reference yet");
                ImGui::EndTabItem();
            }

            if (ImGui::BeginTabItem("Analyse")) {
                if (!C.ofdm_ok) {
                    ImGui::TextColored(ImVec4(1, 0.55f, 0.25f, 1),
                        "OFDM geometry does not close for %.2f Msps at mu=%d",
                        C.rate_hz / 1e6, C.mu);
                } else {
                    int al = g_an_lane.load(), as = g_an_slot.load();
                    ImGui::SetNextItemWidth(110);
                    if (ImGui::SliderInt("lane", &al, 0,
                                         lanes > 0 ? lanes - 1 : 0))
                        g_an_lane.store(al);
                    ImGui::SameLine();
                    ImGui::SetNextItemWidth(130);
                    if (ImGui::SliderInt("slot", &as, 0, C.slots - 1))
                        g_an_slot.store(as);
                    ImGui::SameLine();
                    if (ImGui::Button("Analyse")) {
                        std::lock_guard<std::mutex> g(g_an_mtx);
                        std::fill(g_an_got.begin(), g_an_got.end(), (uint8_t)0);
                        g_an_ready.store(false);
                        g_an_arm.store(true);
                        snprintf(g_an_src, sizeof g_an_src, "%s",
                                 (al < lanes) ? g_lane[al].title : "?");
                        g_an_shown_slot = as;
                    }
                    ImGui::SameLine();
                    if (g_an_arm.load())
                        ImGui::TextColored(ImVec4(1, 0.8f, 0.3f, 1),
                                           "waiting for a complete slot...");
                    else if (g_an_have)
                        ImGui::TextColored(ImVec4(0.6f, 0.75f, 1, 1),
                                           "%s  slot %d", g_an_src,
                                           g_an_shown_slot);

                    if (g_an_have) {
                        ImGui::Text("carrier offset %+.1f Hz  (%+.3f ppm at "
                                    "%.0f MHz)   CP match %.2f",
                                    g_an_Hz, g_an_ppm, C.fc_hz / 1e6, g_an_conf);
                        if (g_an_conf < 0.3f)
                            ImGui::TextColored(ImVec4(1, 0.55f, 0.25f, 1),
                                "  weak CP match - the slot may be empty, or "
                                "the numerology or sample alignment is wrong");
                    }
                    ImGui::SetNextItemWidth(260);
                    ImGui::SliderFloat2("dB range", &g_an_lo_db,
                                        -140.0f, 0.0f, "%.0f");
                    if (g_an_hi_db <= g_an_lo_db) g_an_hi_db = g_an_lo_db + 1.0f;
                }
                ImGui::EndTabItem();
            }

            if (ImGui::BeginTabItem("Timing")) {
                ImGui::TextColored(ImVec4(0.6f, 0.6f, 0.6f, 1),
                    "arrival time compared against the time seq_id implies, "
                    "and the sequence itself");
                for (int i = 0; i < lanes; i++) {
                    lane_t *L = &g_lane[i];
                    ImGui::TextColored(COL[i % MAX_LANES],
                        "  %-26s jitter %+.1f .. %+.1f us   out-of-order %llu"
                        "   duplicate %llu",
                        L->title, L->jit_lo.load(), L->jit_hi.load(),
                        (unsigned long long)L->n_ooo.load(),
                        (unsigned long long)L->n_dup.load());
                }
                ImGui::EndTabItem();
            }

            if (ImGui::BeginTabItem("Stop when")) {
                bool armed = g_armed.load();
                if (ImGui::Checkbox("Armed", &armed)) {
                    g_armed.store(armed);
                    if (armed) {
                        std::lock_guard<std::mutex> g(g_trg_mtx);
                        g_trg_reason[0] = 0;
                    }
                }
                ImGui::SameLine();
                ImGui::TextColored(ImVec4(0.6f, 0.6f, 0.6f, 1),
                                   "with nothing ticked it stops on the next "
                                   "frame (single shot)");

                bool tc = g_trg_cells.load();
                if (ImGui::Checkbox("cells below", &tc)) g_trg_cells.store(tc);
                ImGui::SameLine();
                int cn = g_trg_cells_n.load();
                ImGui::SetNextItemWidth(130);
                if (ImGui::SliderInt("##cn", &cn, 1, C.cells))
                    g_trg_cells_n.store(cn);

                bool ts = g_trg_slot.load();
                if (ImGui::Checkbox("energy in slot", &ts)) g_trg_slot.store(ts);
                ImGui::SameLine();
                int sn = g_trg_slot_n.load();
                ImGui::SetNextItemWidth(130);
                if (ImGui::SliderInt("##sn", &sn, 0, C.slots - 1))
                    g_trg_slot_n.store(sn);

                bool tq = g_trg_silent.load();
                if (ImGui::Checkbox("a sender goes silent", &tq))
                    g_trg_silent.store(tq);
                ImGui::SameLine();
                bool td = g_trg_drop.load();
                if (ImGui::Checkbox("capture loses packets", &td))
                    g_trg_drop.store(td);
                ImGui::EndTabItem();
            }
            ImGui::EndTabBar();
        }

        ImGui::Separator();

        if (lanes == 0) {
            ImGui::Dummy(ImVec2(0, 20));
            ImGui::TextColored(ImVec4(1, 0.8f, 0.3f, 1), "no eCPRI frames yet.");
            ImGui::TextWrapped(
                "Check the interface is up, promiscuous and has an MTU large "
                "enough for the frame, and that the mirror is carrying this "
                "ethertype:  sudo tcpdump -i %s -nn -e -c 5 'ether proto 0x%04x'",
                iface, C.ethertype & 0xffff);
        } else {
            const float gh = g_an_have ? 230.0f : 0.0f;
            if (ImPlot::BeginSubplots("##stack", lanes, 1,
                                      ImVec2(-1, -1 - gh),
                                      ImPlotSubplotFlags_LinkCols)) {
                for (int i = 0; i < lanes; i++)
                    draw_lane(&g_lane[i], i, COL[i % MAX_LANES],
                              i == lanes - 1, stale[i], blank[i]);
                ImPlot::EndSubplots();
            }

            /* resource grid: symbol against resource block, power in dB */
            if (g_an_have) {
                char t[96];
                snprintf(t, sizeof t, "resource grid   %s   slot %d",
                         g_an_src, g_an_shown_slot);
                if (ImPlot::BeginPlot(t, ImVec2(-1, gh - 8.0f),
                                      ImPlotFlags_NoLegend)) {
                    ImPlot::SetupAxes("resource block", "symbol",
                                      ImPlotAxisFlags_Lock,
                                      ImPlotAxisFlags_Lock);
                    ImPlot::SetupAxisLimits(ImAxis_X1, 0, C.nprb,
                                            ImPlotCond_Always);
                    ImPlot::SetupAxisLimits(ImAxis_Y1, 0, C.nsym,
                                            ImPlotCond_Always);
                    ImPlot::PlotHeatmap("##grid", g_an_grid.data(),
                                        C.nsym, C.nprb,
                                        g_an_lo_db, g_an_hi_db, NULL,
                                        ImPlotPoint(0, C.nsym),
                                        ImPlotPoint(C.nprb, 0));
                    ImPlot::EndPlot();
                }
            }
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
