/* -------------------------------------------------------------------------
 * Split 8 fronthaul scope
 *
 * Draws what a digital oscilloscope draws: a min/max envelope of the raw
 * waveform, in linear amplitude, about a true zero baseline. For each
 * eCPRI packet (1920 samples) the smallest and largest I sample are kept
 * and the band between them is filled - the same decimation a scope does
 * per pixel column.
 *
 * Two stacked plots share the slot axis; each direction has its own Y
 * axis, auto-ranged, because the uplink is 30-40 dB below the downlink.
 *
 * Run:  ./build/src/imgui_app <iface> <dl-src-mac>
 *       sudo setcap "cap_net_raw,cap_net_admin=eip" ./build/src/imgui_app
 *       (repeat setcap after every rebuild; do NOT run with sudo)
 *
 * ---------------------------------------------------------------------
 * WHAT THIS REVISION ADDS
 *
 *   TRIGGER - the signal on this testbed walks relative to seq_id, so a
 *     free-running display shows it sliding across the frame. That motion
 *     is real and no display change makes it untrue, but a scope does not
 *     put up with it either: it finds the burst and redraws it at a fixed
 *     position. Same here. The peak cell is located every frame and the
 *     whole frame is rotated so it lands on a latched target. The trace
 *     stands still and the slide becomes a number - see DRIFT below.
 *     Persistence is updated AFTER the rotation, so the band stays sharp
 *     instead of smearing across every position the burst has occupied.
 *     The x axis then reads "slot (triggered)" and the applied shift is
 *     displayed, because the labels no longer mean absolute slots.
 *
 *   DRIFT - the peak cell is tracked frame to frame, unwrapped across the
 *     frame boundary, and fitted against elapsed time. One cell is 1920
 *     samples = 15.625 us, so cells/second converts straight to ppm. The
 *     elapsed time is shown next to it: ppm from a two second baseline is
 *     not worth reading, and the display should say so rather than imply
 *     a precision it does not have.
 *
 *   CURSORS - two vertical and two horizontal draggable cursors per lane,
 *     with a readout of each position and the deltas: slots, microseconds,
 *     samples, packets, and 1/dt as a repetition rate. This is the part
 *     that makes it a measuring instrument rather than a picture.
 *
 *   MEASUREMENTS - per lane: peak cell and slot, burst start/end/width,
 *     duty, peak amplitude, DC mean. Computed on the unrotated data, so
 *     they are true cell indices whether or not the trigger is on.
 *
 *   BLANK ON STOP - a lane that has stopped transmitting used to keep its
 *     last frame on screen for ever and keep claiming 640/640 cells. It
 *     now dims at 0.5 s, and blanks completely - trace, persistence and
 *     axis - once it has been quiet for the blank timeout.
 *
 * EARLIER FIXES, KEPT
 *
 *   Persistence is a phosphor, not a high-water mark: it rises instantly
 *   and decays, so one transient fades instead of pinning the band and
 *   the axis for the whole session. Completed frames are published under
 *   a mutex so the renderer never sees half of one frame and half of the
 *   next. The Y axis rises at once but falls slew-limited, so it cannot
 *   flap. bad and trunc are displayed. "clear" has one flag per lane.
 *
 * KNOWN LIMITATION, UNCHANGED
 *
 *   The trace is min/max of I only. Q is read for the DC mean and is not
 *   plotted. For a complex signal the true envelope is sqrt(I^2 + Q^2);
 *   I alone swings through zero on every carrier cycle even when the
 *   envelope is flat, so some of the fine texture is phase rotation
 *   rather than amplitude. The trigger therefore keys on the per-packet
 *   span (hi - lo), which brackets the whole swing and is far less
 *   phase-sensitive than I itself.
 * ---------------------------------------------------------------------- */

#include <iostream>
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

#define ECPRI_HDR_SIZE    8
#define SAMPLES_PER_PKT   1920
#define PKTS_PER_SLOT     32
#define SLOTS_PER_FRAME   20
#define PKTS_PER_FRAME    640
#define FULL_SCALE        32768.0

/* one packet = 1920 samples at 122.88 Msps */
#define CELL_US           15.625
#define SLOT_US           500.0

/* radio frames arrive at 100/s; turns an afterglow in seconds into a
   per-frame decay coefficient */
#define FRAMES_PER_SEC    100.0f

/* a lane with no completed frame for this long is not live any more */
#define STALE_US          500000ULL

/* a burst cell is one whose span rises this far above the frame's peak
   span; the absolute floor stops noise from registering as a burst */
#define BURST_FRAC        0.10f
#define BURST_FLOOR       (8.0f / (float)FULL_SCALE)

/* A real frame wrap goes 639 -> 0.  A reordering of two packets goes 7 -> 6,
   which is also a backward step - treating that as a wrap cuts the frame
   after a couple of packets and collapses the cell count. Only a large
   backward jump is a wrap. */
#define WRAP_MIN          (PKTS_PER_FRAME / 2)

static uint64_t now_us(void)
{
    using namespace std::chrono;
    return (uint64_t)duration_cast<microseconds>(
               steady_clock::now().time_since_epoch()).count();
}

/* ------------------------------------------------------- shared with the UI
   One of these per direction. Written by the capture thread in finish_frame,
   read by the render thread in draw_trace, both under g_env_mtx. */
typedef struct {
    float lo[PKTS_PER_FRAME],  hi[PKTS_PER_FRAME];    /* live, as displayed */
    float plo[PKTS_PER_FRAME], phi[PKTS_PER_FRAME];   /* persistence        */
    float dc_i, dc_q;                                 /* mean, in LSB       */

    /* measurements, always in TRUE cell indices - never rotated */
    int   peak_cell;        /* -1 when no burst was found */
    float peak_span;
    float peak_abs;
    int   b0, b1;           /* first and last burst cell, -1 when none */
    int   nburst;
    int   shift;            /* cells the display was rotated by */
} env_t;

static env_t      g_env[2];          /* [0] = UL, [1] = DL */
static std::mutex g_env_mtx[2];

static std::atomic<uint32_t> g_cells[2];
static std::atomic<uint64_t> g_last_us[2];           /* last completed frame */

static std::atomic<uint32_t> g_drop(0), g_ifdrop(0);
static std::atomic<uint64_t> g_bad(0), g_trunc(0);
static std::atomic<bool>     g_running(true);
static std::atomic<bool>     g_measure_dc(false);

/* trigger */
static std::atomic<bool> g_trigger(false);
static std::atomic<int>  g_target[2];        /* cell the peak is pinned to */
static std::atomic<bool> g_relatch[2];       /* re-latch the target */

/* drift, published by the capture thread */
static std::atomic<double> g_ppm[2];
static std::atomic<double> g_drift_secs[2];
static std::atomic<bool>   g_drift_reset[2];

/* one flag per direction: a single shared flag was consumed by whichever
   finish_frame ran first, so only one lane ever cleared */
static std::atomic<bool> g_reset[2];

static pcap_t      *g_ph = NULL;
static unsigned char g_dl_mac[6];

static bool  g_persist    = true;
static bool  g_autofit    = true;
static bool  g_cursors    = false;
static float g_afterglow  = 3.0f;    /* seconds; 0 = hold for ever */
static float g_blank_secs = 3.0f;    /* blank a silent lane after this */

/* cursor positions, [lane][0..1] */
static double g_cx[2][2] = { { 4.0, 8.0 }, { 4.0, 8.0 } };
static double g_cy[2][2] = { { -0.1, 0.1 }, { -0.1, 0.1 } };

/* ------------------------------------------------- capture-thread state only */
typedef struct {
    int16_t  mn[PKTS_PER_FRAME];
    int16_t  mx[PKTS_PER_FRAME];
    int32_t  si[PKTS_PER_FRAME];     /* sum of I over the packet */
    int32_t  sq[PKTS_PER_FRAME];     /* sum of Q over the packet */
    uint8_t  seen[PKTS_PER_FRAME];

    float    lo[PKTS_PER_FRAME],  hi[PKTS_PER_FRAME];    /* true order   */
    float    rlo[PKTS_PER_FRAME], rhi[PKTS_PER_FRAME];   /* rotated      */
    float    plo[PKTS_PER_FRAME], phi[PKTS_PER_FRAME];   /* persistence  */

    /* drift tracking */
    double   pos;            /* unwrapped peak position, in cells */
    int      last_peak;
    int      track_init;
    double   pos0;
    uint64_t t0;

    uint32_t last_cell;
    int      started;
    int      idx;            /* 1 = DL, 0 = UL */
} dir_t;

static dir_t g_dl, g_ul;

static void finish_frame(dir_t *d)
{
    const int k_idx = d->idx;
    bool clear = g_reset[k_idx].exchange(false);

    float k = 0.0f;
    if (g_afterglow > 0.01f)
        k = 1.0f - expf(-1.0f / (FRAMES_PER_SEC * g_afterglow));

    uint32_t have = 0;
    int64_t  tot_i = 0, tot_q = 0;

    /* pass 1: true-order envelope, peak, DC */
    int   peak_cell = -1;
    float peak_span = 0.0f, peak_abs = 0.0f;

    for (uint32_t c = 0; c < PKTS_PER_FRAME; c++) {
        have += d->seen[c];

        float a = (float)d->mn[c] / (float)FULL_SCALE;
        float b = (float)d->mx[c] / (float)FULL_SCALE;
        d->lo[c] = a;
        d->hi[c] = b;

        float span = b - a;
        if (span > peak_span) { peak_span = span; peak_cell = (int)c; }
        if (fabsf(a) > peak_abs) peak_abs = fabsf(a);
        if (fabsf(b) > peak_abs) peak_abs = fabsf(b);

        tot_i += d->si[c];
        tot_q += d->sq[c];

        d->mn[c] = 0;  d->mx[c] = 0;
        d->si[c] = 0;  d->sq[c] = 0;
    }
    memset(d->seen, 0, sizeof d->seen);

    /* a peak that is only noise is not a burst */
    if (peak_span < BURST_FLOOR) { peak_cell = -1; peak_span = 0.0f; }

    /* pass 2: burst extent, on the true order */
    int b0 = -1, b1 = -1, nburst = 0;
    if (peak_cell >= 0) {
        float thr = peak_span * BURST_FRAC;
        if (thr < BURST_FLOOR) thr = BURST_FLOOR;
        for (int c = 0; c < PKTS_PER_FRAME; c++) {
            if (d->hi[c] - d->lo[c] >= thr) {
                if (b0 < 0) b0 = c;
                b1 = c;
                nburst++;
            }
        }
    }

    /* drift: track the peak, unwrapped across the frame boundary */
    uint64_t now = now_us();
    if (peak_cell >= 0) {
        if (!d->track_init) {
            d->track_init = 1;
            d->pos = d->pos0 = peak_cell;
            d->last_peak = peak_cell;
            d->t0 = now;
        } else {
            int delta = peak_cell - d->last_peak;
            if (delta >  PKTS_PER_FRAME / 2) delta -= PKTS_PER_FRAME;
            if (delta < -PKTS_PER_FRAME / 2) delta += PKTS_PER_FRAME;
            d->pos += delta;
            d->last_peak = peak_cell;
        }
    }
    if (g_drift_reset[k_idx].exchange(false)) {
        d->pos0 = d->pos;
        d->t0   = now;
    }
    if (d->track_init && now > d->t0) {
        double secs = (double)(now - d->t0) / 1e6;
        /* one cell is 15.625 us, so cells/second is already ppm */
        g_ppm[k_idx].store((d->pos - d->pos0) * CELL_US / secs);
        g_drift_secs[k_idx].store(secs);
    }

    /* trigger: rotate so the peak lands on the latched target */
    int shift = 0;
    if (g_trigger.load() && peak_cell >= 0) {
        if (g_relatch[k_idx].exchange(false) || g_target[k_idx].load() < 0)
            g_target[k_idx].store(peak_cell);
        int tgt = g_target[k_idx].load();
        shift = peak_cell - tgt;
        shift %= PKTS_PER_FRAME;
        if (shift < 0) shift += PKTS_PER_FRAME;
    }

    const float *slo = d->lo, *shi = d->hi;
    if (shift) {
        for (int c = 0; c < PKTS_PER_FRAME; c++) {
            int s = (c + shift) % PKTS_PER_FRAME;
            d->rlo[c] = d->lo[s];
            d->rhi[c] = d->hi[s];
        }
        slo = d->rlo; shi = d->rhi;
    }

    /* persistence is updated AFTER the rotation, so with the trigger on it
       accumulates aligned frames and stays sharp */
    for (int c = 0; c < PKTS_PER_FRAME; c++) {
        float a = slo[c], b = shi[c];
        if (clear) { d->plo[c] = a; d->phi[c] = b; }
        else {
            d->phi[c] = (b > d->phi[c]) ? b : d->phi[c] + (b - d->phi[c]) * k;
            d->plo[c] = (a < d->plo[c]) ? a : d->plo[c] + (a - d->plo[c]) * k;
        }
    }

    const double n = (double)PKTS_PER_FRAME * (double)SAMPLES_PER_PKT;

    {
        env_t *E = &g_env[k_idx];
        std::lock_guard<std::mutex> lk(g_env_mtx[k_idx]);
        memcpy(E->lo,  slo,    sizeof E->lo);
        memcpy(E->hi,  shi,    sizeof E->hi);
        memcpy(E->plo, d->plo, sizeof E->plo);
        memcpy(E->phi, d->phi, sizeof E->phi);
        E->dc_i      = (float)((double)tot_i / n);
        E->dc_q      = (float)((double)tot_q / n);
        E->peak_cell = peak_cell;
        E->peak_span = peak_span;
        E->peak_abs  = peak_abs;
        E->b0        = b0;
        E->b1        = b1;
        E->nburst    = nburst;
        E->shift     = shift;
    }

    g_cells[k_idx].store(have);
    g_last_us[k_idx].store(now);
}

/* hot path: one pass over the samples, integer compares only */
static void on_packet(unsigned char *user, const struct pcap_pkthdr *h,
                      const unsigned char *bytes)
{
    (void)user;

    if (h->caplen < 14 + ECPRI_HDR_SIZE + SAMPLES_PER_PKT * 4) { g_trunc++; return; }

    const unsigned char *b = bytes + 14;
    if (((b[0] >> 4) & 0x0F) != 1 || b[1] != 0x00) { g_bad++; return; }

    uint16_t v;
    memcpy(&v, b + 6, 2);
    uint16_t seq = ntohs(v);
    if (seq < 1 || seq > PKTS_PER_FRAME) { g_bad++; return; }

    uint32_t cell = (uint32_t)seq - 1;

    int is_dl = (memcmp(bytes + 6, g_dl_mac, 6) == 0);
    dir_t *d  = is_dl ? &g_dl : &g_ul;

    /* only a large backward jump is a frame wrap; a small one is a
       reordering and must not split the frame in two */
    if (d->started && cell < d->last_cell &&
        d->last_cell - cell > WRAP_MIN) finish_frame(d);
    d->started   = 1;
    d->last_cell = cell;

    const int16_t *iq = (const int16_t *)(b + ECPRI_HDR_SIZE);

    int16_t mn = 0, mx = 0;

    if (g_measure_dc.load(std::memory_order_relaxed)) {
        /* Q lives in the same cache line as I, so this costs arithmetic
           rather than memory traffic. Max |sum| is 1920 * 32768, which
           fits int32 with room to spare. */
        int32_t si = 0, sq = 0;
        for (int i = 0; i < SAMPLES_PER_PKT; i++) {
            int16_t I = iq[2 * i];
            int16_t Q = iq[2 * i + 1];
            if (I < mn) mn = I;
            if (I > mx) mx = I;
            si += I;
            sq += Q;
        }
        d->si[cell] = si;
        d->sq[cell] = sq;
    } else {
        for (int i = 0; i < SAMPLES_PER_PKT; i++) {
            int16_t I = iq[2 * i];
            if (I < mn) mn = I;
            if (I > mx) mx = I;
        }
        d->si[cell] = 0;
        d->sq[cell] = 0;
    }

    d->mn[cell]   = mn;
    d->mx[cell]   = mx;
    d->seen[cell] = 1;
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
            pd = st.ps_drop;
            pi = st.ps_ifdrop;
        }
    }
}

static void capture_thread(const char *iface)
{
    char err[PCAP_ERRBUF_SIZE] = {0};

    g_ph = pcap_create(iface, err);
    if (!g_ph) { std::cerr << "pcap_create: " << err << "\n"; return; }

    pcap_set_snaplen(g_ph, 9000);
    pcap_set_promisc(g_ph, 1);
    pcap_set_timeout(g_ph, 10);
    pcap_set_buffer_size(g_ph, 256 * 1024 * 1024);

    if (pcap_activate(g_ph) < 0) {
        std::cerr << "pcap_activate: " << pcap_geterr(g_ph) << "\n";
        return;
    }

    struct bpf_program fp;
    if (pcap_compile(g_ph, &fp, "ether proto 0xaefe", 1,
                     PCAP_NETMASK_UNKNOWN) == 0) {
        pcap_setfilter(g_ph, &fp);
        pcap_freecode(&fp);
    }

    pcap_loop(g_ph, -1, on_packet, NULL);
}

static void glfwErrorCallback(int e, const char *d)
{
    std::cerr << "GLFW error " << e << ": " << d << '\n';
}

static double g_xs[PKTS_PER_FRAME];
static double g_grid[SLOTS_PER_FRAME + 1];
static double g_lo[PKTS_PER_FRAME], g_hi[PKTS_PER_FRAME];
static double g_plo[PKTS_PER_FRAME], g_phi[PKTS_PER_FRAME];
static double g_mid[PKTS_PER_FRAME];

/* one held span per lane, so the axis can rise at once but only fall slowly */
static double g_span_hold[2] = { 1e-4, 1e-4 };

static double      g_tick_pos[SLOTS_PER_FRAME];
static char        g_tick_buf[SLOTS_PER_FRAME][4];
static const char *g_tick_lbl[SLOTS_PER_FRAME];

static void draw_trace(const char *title, int idx, ImVec4 col, bool show_x,
                       bool stale, bool blank)
{
    if (blank) {
        for (int c = 0; c < PKTS_PER_FRAME; c++)
            g_lo[c] = g_hi[c] = g_plo[c] = g_phi[c] = g_mid[c] = 0.0;
        g_span_hold[idx] = 1e-4;     /* let the axis come back down too */
    } else {
        std::lock_guard<std::mutex> lk(g_env_mtx[idx]);
        const env_t *E = &g_env[idx];
        for (int c = 0; c < PKTS_PER_FRAME; c++) {
            g_lo[c]  = E->lo[c];   g_hi[c]  = E->hi[c];
            g_plo[c] = E->plo[c];  g_phi[c] = E->phi[c];
        }
    }

    /* a lane that has stopped is showing an old frame - dim it so it cannot
       be mistaken for something live */
    if (stale) { col.x *= 0.35f; col.y *= 0.35f; col.z *= 0.35f; }

    double target = 1e-6;
    for (int c = 0; c < PKTS_PER_FRAME; c++) {
        if (fabs(g_hi[c]) > target) target = fabs(g_hi[c]);
        if (fabs(g_lo[c]) > target) target = fabs(g_lo[c]);
        if (g_persist) {
            if (fabs(g_phi[c]) > target) target = fabs(g_phi[c]);
            if (fabs(g_plo[c]) > target) target = fabs(g_plo[c]);
        }
    }
    if (target < 1e-4) target = 1e-4;     /* floor, so it can never collapse */
    target *= 1.15;

    double *S = &g_span_hold[idx];
    *S = (target > *S) ? target : *S + (target - *S) * 0.05;
    double span = *S;

    ImPlotAxisFlags xf = ImPlotAxisFlags_Lock;
    if (!show_x) xf |= ImPlotAxisFlags_NoTickLabels;

    const char *xlabel = NULL;
    if (show_x) xlabel = g_trigger.load() ? "slot (triggered)" : "slot";

    if (ImPlot::BeginPlot(title, ImVec2(-1, -1), ImPlotFlags_NoLegend)) {
        ImPlot::SetupAxes(xlabel, "amplitude", xf, ImPlotAxisFlags_Lock);
        ImPlot::SetupAxisLimits(ImAxis_X1, 0, SLOTS_PER_FRAME, ImPlotCond_Always);
        ImPlot::SetupAxisLimits(ImAxis_Y1,
                                g_autofit ? -span : -1.0,
                                g_autofit ?  span :  1.0,
                                ImPlotCond_Always);
        ImPlot::SetupAxisTicks(ImAxis_X1, g_tick_pos, SLOTS_PER_FRAME, g_tick_lbl);

        /* slot boundaries */
        ImPlot::SetNextLineStyle(ImVec4(0.45f, 0.45f, 0.45f, 0.30f), 1.0f);
        ImPlot::PlotInfLines("##grid", g_grid, SLOTS_PER_FRAME + 1);

        if (!blank) {
            if (g_persist) {
                ImPlot::SetNextFillStyle(col, 0.20f);
                ImPlot::PlotShaded("##persist", g_xs, g_plo, g_phi, PKTS_PER_FRAME);
            }
            ImPlot::SetNextFillStyle(col, 1.0f);
            ImPlot::PlotShaded("##env", g_xs, g_lo, g_hi, PKTS_PER_FRAME);

            /* centre line, so the trace stays continuous through silent slots
             * where min and max are both zero and the band has no height */
            for (int c = 0; c < PKTS_PER_FRAME; c++)
                g_mid[c] = 0.5 * (g_lo[c] + g_hi[c]);
            ImPlot::SetNextLineStyle(col, 1.6f);
            ImPlot::PlotLine("##mid", g_xs, g_mid, PKTS_PER_FRAME);
        }

        if (g_cursors) {
            const ImVec4 cxc(0.95f, 0.35f, 0.35f, 1.0f);   /* x cursors, red  */
            const ImVec4 cyc(0.45f, 0.65f, 1.00f, 1.0f);   /* y cursors, blue */
            ImPlot::DragLineX(idx * 10 + 0, &g_cx[idx][0], cxc, 1.5f);
            ImPlot::DragLineX(idx * 10 + 1, &g_cx[idx][1], cxc, 1.5f);
            ImPlot::DragLineY(idx * 10 + 2, &g_cy[idx][0], cyc, 1.5f);
            ImPlot::DragLineY(idx * 10 + 3, &g_cy[idx][1], cyc, 1.5f);
        }

        ImPlot::EndPlot();
    }
}

/* one line of measurements for a lane, in true cell indices */
static void lane_status(const char *name, int idx, uint64_t now, bool blank)
{
    uint64_t last = g_last_us[idx].load();

    if (last == 0) {
        ImGui::TextColored(ImVec4(0.6f, 0.6f, 0.6f, 1),
                           "  %s  no frame yet", name);
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
                           "  %s  STALE %.1f s  -- showing the last frame, "
                           "not live", name, age / 1e6);
        return;
    }

    env_t E;
    {
        std::lock_guard<std::mutex> lk(g_env_mtx[idx]);
        E = g_env[idx];
    }

    char dcbuf[64] = "";
    if (g_measure_dc.load())
        snprintf(dcbuf, sizeof dcbuf, "   DC I=%+.0f Q=%+.0f (%.2f%% FS)",
                 E.dc_i, E.dc_q,
                 100.0 * sqrt((double)E.dc_i * E.dc_i +
                              (double)E.dc_q * E.dc_q) / FULL_SCALE);

    ImGui::Text("  %s  %u/640 cells   peak %.4f%s",
                name, g_cells[idx].load(), E.peak_abs, dcbuf);

    if (E.peak_cell < 0) {
        ImGui::TextColored(ImVec4(0.6f, 0.6f, 0.6f, 1),
                           "      no burst above the noise floor");
        return;
    }

    double width_cells = (double)(E.b1 - E.b0 + 1);
    ImGui::Text("      peak cell %d (slot %.2f)   burst cells %d..%d = "
                "slot %.2f..%.2f   width %.0f us (%d cells)   duty %.1f%%",
                E.peak_cell, E.peak_cell / (double)PKTS_PER_SLOT,
                E.b0, E.b1,
                E.b0 / (double)PKTS_PER_SLOT,
                (E.b1 + 1) / (double)PKTS_PER_SLOT,
                width_cells * CELL_US, (int)width_cells,
                100.0 * E.nburst / (double)PKTS_PER_FRAME);

    double ppm  = g_ppm[idx].load();
    double secs = g_drift_secs[idx].load();
    ImVec4 pc = (secs < 30.0) ? ImVec4(0.65f, 0.65f, 0.65f, 1)
                              : ImVec4(1.0f, 0.8f, 0.3f, 1);
    ImGui::TextColored(pc,
        "      drift %+.3f ppm over %.0f s%s%s",
        ppm, secs,
        (secs < 30.0) ? "  (too short to trust)" : "",
        g_trigger.load() ? "" : "  -- trigger off, trace is free-running");
}

static void cursor_readout(const char *name, int idx)
{
    double x0 = g_cx[idx][0], x1 = g_cx[idx][1];
    double y0 = g_cy[idx][0], y1 = g_cy[idx][1];
    double dx = fabs(x1 - x0);
    double dy = fabs(y1 - y0);
    double dt_us = dx * SLOT_US;

    char rate[48] = "";
    if (dt_us > 1e-9) {
        double hz = 1e6 / dt_us;
        if (hz >= 1000.0) snprintf(rate, sizeof rate, "   1/dt = %.3f kHz", hz / 1000.0);
        else              snprintf(rate, sizeof rate, "   1/dt = %.1f Hz", hz);
    }

    ImGui::Text("  %s cursors   x %.3f .. %.3f slot   dx %.3f slot = "
                "%.1f us = %.0f samples = %.1f packets%s",
                name, x0, x1, dx, dt_us,
                dx * (double)PKTS_PER_SLOT * SAMPLES_PER_PKT,
                dx * (double)PKTS_PER_SLOT, rate);
    ImGui::Text("              y %+.5f .. %+.5f   dy %.5f   "
                "= %.0f counts of full scale",
                y0, y1, dy, dy * FULL_SCALE);
}

int main(int argc, char **argv)
{
    if (argc < 3) {
        std::cerr << "usage: " << argv[0] << " <iface> <dl-src-mac>\n";
        return 1;
    }

    unsigned int m[6];
    if (sscanf(argv[2], "%x:%x:%x:%x:%x:%x",
               &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]) != 6) {
        std::cerr << "bad MAC: " << argv[2] << "\n";
        return 1;
    }
    for (int i = 0; i < 6; i++) g_dl_mac[i] = (unsigned char)m[i];

    memset(&g_dl, 0, sizeof g_dl);
    memset(&g_ul, 0, sizeof g_ul);
    g_dl.idx = 1;
    g_ul.idx = 0;
    g_target[0].store(-1);
    g_target[1].store(-1);

    for (int c = 0; c < PKTS_PER_FRAME; c++)
        g_xs[c] = (double)c / (double)PKTS_PER_SLOT;   /* x in slot units */

    for (int s = 0; s <= SLOTS_PER_FRAME; s++) g_grid[s] = s;
    for (int s = 0; s < SLOTS_PER_FRAME; s++) {
        g_tick_pos[s] = s + 0.5;
        snprintf(g_tick_buf[s], sizeof g_tick_buf[s], "%d", s);
        g_tick_lbl[s] = g_tick_buf[s];
    }

    glfwSetErrorCallback(glfwErrorCallback);
    if (!glfwInit()) { std::cerr << "glfwInit failed\n"; return 1; }

    glfwDefaultWindowHints();
    GLFWwindow *window = glfwCreateWindow(1500, 940,
                                          "Split 8 fronthaul scope",
                                          nullptr, nullptr);
    if (!window) { std::cerr << "no window - is DISPLAY set?\n"; glfwTerminate(); return 1; }

    glfwMakeContextCurrent(window);
    glfwSwapInterval(1);

    if (glewInit() != GLEW_OK) { std::cerr << "glewInit failed\n"; return 1; }

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImPlot::CreateContext();
    ImGui::StyleColorsDark();

    ImGuiIO &io = ImGui::GetIO();
    io.FontGlobalScale = 1.25f;

    ImGui_ImplGlfw_InitForOpenGL(window, true);
    ImGui_ImplOpenGL3_Init("#version 130");

    std::thread cap(capture_thread, argv[1]);
    std::thread sta(stats_thread);

    const ImVec4 COL_DL(1.00f, 0.85f, 0.10f, 1.0f);   /* scope yellow */
    const ImVec4 COL_UL(0.20f, 0.95f, 0.35f, 1.0f);   /* scope green  */

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

        uint64_t now  = now_us();
        uint32_t drop = g_drop.load(), ifdrop = g_ifdrop.load();

        uint64_t blank_us = (uint64_t)(g_blank_secs * 1e6);
        bool live[2], stale[2], blank[2];
        for (int i = 0; i < 2; i++) {
            uint64_t last = g_last_us[i].load();
            live[i]  = (last != 0);
            uint64_t age = live[i] ? now - last : 0;
            stale[i] = live[i] && age > STALE_US;
            blank[i] = live[i] && age > blank_us;
        }

        ImGui::Text("%s   DL src %s", argv[1], argv[2]);

        if (drop || ifdrop)
            ImGui::TextColored(ImVec4(1, 0.25f, 0.25f, 1),
                               "LOSSY  drop=+%u ifdrop=+%u   -- trace has holes",
                               drop, ifdrop);
        else
            ImGui::TextColored(ImVec4(0.3f, 1, 0.3f, 1), "clean  drop=0 ifdrop=0");

        if (g_bad.load() || g_trunc.load())
            ImGui::TextColored(ImVec4(1, 0.8f, 0.3f, 1),
                               "rejected: bad=%llu trunc=%llu",
                               (unsigned long long)g_bad.load(),
                               (unsigned long long)g_trunc.load());

        lane_status("DL", 1, now, blank[1]);
        lane_status("UL", 0, now, blank[0]);

        if (g_cursors) {
            cursor_readout("DL", 1);
            cursor_readout("UL", 0);
        }

        /* row 1: display */
        ImGui::Checkbox("persistence", &g_persist);
        ImGui::SameLine();
        if (ImGui::Button("clear")) { g_reset[0].store(true); g_reset[1].store(true); }
        ImGui::SameLine();
        ImGui::Checkbox("auto range", &g_autofit);
        ImGui::SameLine();
        ImGui::SetNextItemWidth(180);
        ImGui::SliderFloat("afterglow", &g_afterglow, 0.0f, 20.0f,
                           g_afterglow < 0.01f ? "hold" : "%.1f s");
        ImGui::SameLine();
        ImGui::SetNextItemWidth(180);
        ImGui::SliderFloat("blank after", &g_blank_secs, 1.0f, 30.0f, "%.0f s");

        /* row 2: measurement */
        bool trig = g_trigger.load();
        if (ImGui::Checkbox("trigger", &trig)) {
            g_trigger.store(trig);
            if (trig) { g_relatch[0].store(true); g_relatch[1].store(true); }
        }
        ImGui::SameLine();
        if (ImGui::Button("re-centre")) {
            g_relatch[0].store(true);
            g_relatch[1].store(true);
        }
        ImGui::SameLine();
        ImGui::Checkbox("cursors", &g_cursors);
        ImGui::SameLine();
        bool dc = g_measure_dc.load();
        if (ImGui::Checkbox("measure DC", &dc)) g_measure_dc.store(dc);
        ImGui::SameLine();
        if (ImGui::Button("reset drift")) {
            g_drift_reset[0].store(true);
            g_drift_reset[1].store(true);
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
