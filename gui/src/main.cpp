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
 * CHANGES IN THIS REVISION - all six came out of one screenshot where the
 * terminal tool read "UL 0 pkts, all slots -120 dBFS" while this one drew
 * a full-height band and claimed 640/640 cells UL.
 *
 *   1. PERSISTENCE WAS A HIGH-WATER MARK, NOT A PHOSPHOR.
 *      "if (b > phi[c]) phi[c] = b" only ever rises. One transient - a
 *      glitched frame, a reordering, a clipped packet - widened the band
 *      permanently, and since the Y axis is derived from the band, that
 *      single spike rescaled the axis for the rest of the session and
 *      flattened the live trace. It now rises instantly and decays with a
 *      time constant you can set, which is what a real phosphor does.
 *      afterglow = 0 restores the old infinite hold.
 *
 *   2. THE ENVELOPE ARRAYS WERE SHARED ACROSS THREADS WITH NO LOCK.
 *      finish_frame (capture thread) wrote the same plain float arrays
 *      draw_trace (render thread) was reading, so the renderer could copy
 *      the first half of one frame and the second half of the next and
 *      show a vertical discontinuity at random. Each completed frame is
 *      now published under a mutex. The lock is held for about 5 us at
 *      100 frames/s - 0.05% duty on the capture thread.
 *
 *   3. THE Y AXIS COULD JUMP FRAME TO FRAME.
 *      It rises immediately, so a real signal is never clipped, but falls
 *      with a slew limit, so it cannot flap.
 *
 *   4. bad AND trunc WERE COUNTED AND NEVER SHOWN.
 *      A sender numbering its packets 0..639 instead of 1..640 would have
 *      every seq_id 0 silently discarded and the whole axis offset by one
 *      cell, with nothing on screen to say so.
 *
 *   5. A SILENT LANE KEPT SHOWING ITS LAST FRAME FOR EVER.
 *      The envelope is only written in finish_frame, so when a direction
 *      goes quiet the last completed frame stays on screen and the cell
 *      count keeps reporting 640/640 from whenever that was. Each lane now
 *      carries the age of its last completed frame; past 500 ms it is
 *      drawn dimmed and labelled stale instead of claiming to be live.
 *
 *   6. OPTIONAL DC MEASUREMENT.
 *      A constant added to I or Q does not average away, so it reads as
 *      the same power in every slot whether or not anything is being
 *      transmitted - which is what "every uplink slot at -30.9 dBFS"
 *      looks like. Noise and tones both have zero mean; a DC offset does
 *      not. The mean of I and Q over the frame separates them. Off by
 *      default because it adds two accumulations per sample to the hot
 *      loop; turn it on and watch that drop stays at 0.
 *
 *   7. "clear" cleared only one of the two lanes (kept from before). The
 *      flag was consumed with exchange(false), so whichever direction's
 *      finish_frame ran first took it. Two flags now, one per direction.
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

/* radio frames arrive at 100/s; turns an afterglow in seconds into a
   per-frame decay coefficient */
#define FRAMES_PER_SEC    100.0f

/* a lane with no completed frame for this long is not live any more */
#define STALE_US          500000ULL

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
   read by the render thread in draw_trace, both under g_env_mtx. Nothing
   else crosses the thread boundary except the atomics below. */
typedef struct {
    float lo[PKTS_PER_FRAME],  hi[PKTS_PER_FRAME];    /* live envelope */
    float plo[PKTS_PER_FRAME], phi[PKTS_PER_FRAME];   /* persistence   */
    float dc_i, dc_q;                                 /* mean, in LSB  */
} env_t;

static env_t      g_env[2];          /* [0] = UL, [1] = DL */
static std::mutex g_env_mtx[2];

static std::atomic<uint32_t> g_cells[2];
static std::atomic<uint64_t> g_last_us[2];           /* last completed frame */

static std::atomic<uint32_t> g_drop(0), g_ifdrop(0);
static std::atomic<uint64_t> g_bad(0), g_trunc(0);
static std::atomic<bool>     g_running(true);
static std::atomic<bool>     g_measure_dc(false);

/* one flag per direction: a single shared flag was consumed by whichever
   finish_frame ran first, so only one lane ever cleared */
static std::atomic<bool>     g_reset[2];

static pcap_t      *g_ph = NULL;
static unsigned char g_dl_mac[6];

static bool  g_persist   = true;
static bool  g_autofit   = true;
static float g_afterglow = 3.0f;     /* seconds; 0 = hold for ever */

/* ------------------------------------------------- capture-thread state only */
typedef struct {
    int16_t  mn[PKTS_PER_FRAME];
    int16_t  mx[PKTS_PER_FRAME];
    int32_t  si[PKTS_PER_FRAME];     /* sum of I over the packet */
    int32_t  sq[PKTS_PER_FRAME];     /* sum of Q over the packet */
    uint8_t  seen[PKTS_PER_FRAME];

    float    lo[PKTS_PER_FRAME],  hi[PKTS_PER_FRAME];
    float    plo[PKTS_PER_FRAME], phi[PKTS_PER_FRAME];

    uint32_t last_cell;
    int      started;
    int      idx;                    /* 1 = DL, 0 = UL */
} dir_t;

static dir_t g_dl, g_ul;

static void finish_frame(dir_t *d)
{
    const int k_idx = d->idx;
    bool clear = g_reset[k_idx].exchange(false);

    /* Phosphor, not a high-water mark. Rise instantly so nothing real is
       missed; decay towards the live value so one transient fades instead
       of pinning the band - and the axis - for the whole session. */
    float k = 0.0f;
    if (g_afterglow > 0.01f)
        k = 1.0f - expf(-1.0f / (FRAMES_PER_SEC * g_afterglow));

    uint32_t have = 0;
    int64_t  tot_i = 0, tot_q = 0;

    for (uint32_t c = 0; c < PKTS_PER_FRAME; c++) {
        have += d->seen[c];

        float a = (float)d->mn[c] / (float)FULL_SCALE;
        float b = (float)d->mx[c] / (float)FULL_SCALE;

        d->lo[c] = a;
        d->hi[c] = b;

        if (clear) {
            d->plo[c] = a;
            d->phi[c] = b;
        } else {
            d->phi[c] = (b > d->phi[c]) ? b : d->phi[c] + (b - d->phi[c]) * k;
            d->plo[c] = (a < d->plo[c]) ? a : d->plo[c] + (a - d->plo[c]) * k;
        }

        tot_i += d->si[c];
        tot_q += d->sq[c];

        d->mn[c] = 0;  d->mx[c] = 0;
        d->si[c] = 0;  d->sq[c] = 0;
    }

    memset(d->seen, 0, sizeof d->seen);

    const double n = (double)PKTS_PER_FRAME * (double)SAMPLES_PER_PKT;

    /* publish the whole frame at once: the renderer must never see half of
       one frame and half of the next */
    {
        env_t *E = &g_env[k_idx];
        std::lock_guard<std::mutex> lk(g_env_mtx[k_idx]);
        memcpy(E->lo,  d->lo,  sizeof E->lo);
        memcpy(E->hi,  d->hi,  sizeof E->hi);
        memcpy(E->plo, d->plo, sizeof E->plo);
        memcpy(E->phi, d->phi, sizeof E->phi);
        E->dc_i = (float)((double)tot_i / n);
        E->dc_q = (float)((double)tot_q / n);
    }

    g_cells[k_idx].store(have);
    g_last_us[k_idx].store(now_us());
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
                       bool stale)
{
    /* take one consistent frame, then let go of the lock immediately */
    {
        std::lock_guard<std::mutex> lk(g_env_mtx[idx]);
        const env_t *E = &g_env[idx];
        for (int c = 0; c < PKTS_PER_FRAME; c++) {
            g_lo[c]  = E->lo[c];   g_hi[c]  = E->hi[c];
            g_plo[c] = E->plo[c];  g_phi[c] = E->phi[c];
        }
    }

    /* a lane that has stopped sending is showing an old frame - dim it so
       it cannot be mistaken for something live */
    if (stale) { col.x *= 0.35f; col.y *= 0.35f; col.z *= 0.35f; }

    /* the scale must follow what is actually drawn. Deriving it from the
       persistence arrays alone meant that clearing them collapsed the axis
       to the 1e-6 seed and the live trace fell outside it. */
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

    /* rise at once so a real signal is never clipped, fall slowly so the
       axis cannot flap from frame to frame */
    double *S = &g_span_hold[idx];
    *S = (target > *S) ? target : *S + (target - *S) * 0.05;
    double span = *S;

    ImPlotAxisFlags xf = ImPlotAxisFlags_Lock;
    if (!show_x) xf |= ImPlotAxisFlags_NoTickLabels;

    if (ImPlot::BeginPlot(title, ImVec2(-1, -1), ImPlotFlags_NoLegend)) {
        ImPlot::SetupAxes(show_x ? "slot" : NULL, "amplitude", xf, ImPlotAxisFlags_Lock);
        ImPlot::SetupAxisLimits(ImAxis_X1, 0, SLOTS_PER_FRAME, ImPlotCond_Always);
        ImPlot::SetupAxisLimits(ImAxis_Y1,
                                g_autofit ? -span : -1.0,
                                g_autofit ?  span :  1.0,
                                ImPlotCond_Always);
        ImPlot::SetupAxisTicks(ImAxis_X1, g_tick_pos, SLOTS_PER_FRAME, g_tick_lbl);

        /* slot boundaries */
        ImPlot::SetNextLineStyle(ImVec4(0.45f, 0.45f, 0.45f, 0.30f), 1.0f);
        ImPlot::PlotInfLines("##grid", g_grid, SLOTS_PER_FRAME + 1);

        /* persistence band, like a scope's afterglow */
        if (g_persist) {
            ImPlot::SetNextFillStyle(col, 0.20f);
            ImPlot::PlotShaded("##persist", g_xs, g_plo, g_phi, PKTS_PER_FRAME);
        }

        /* live envelope */
        ImPlot::SetNextFillStyle(col, 1.0f);
        ImPlot::PlotShaded("##env", g_xs, g_lo, g_hi, PKTS_PER_FRAME);

        /* centre line, so the trace stays continuous through silent slots
         * where min and max are both zero and the band has no height */
        for (int c = 0; c < PKTS_PER_FRAME; c++)
            g_mid[c] = 0.5 * (g_lo[c] + g_hi[c]);
        ImPlot::SetNextLineStyle(col, 1.6f);
        ImPlot::PlotLine("##mid", g_xs, g_mid, PKTS_PER_FRAME);

        ImPlot::EndPlot();
    }
}

static void lane_status(const char *name, int idx, uint64_t now)
{
    uint64_t last = g_last_us[idx].load();
    uint64_t age  = (last == 0) ? 0 : now - last;

    if (last == 0) {
        ImGui::TextColored(ImVec4(0.6f, 0.6f, 0.6f, 1),
                           "  %s  no frame yet", name);
        return;
    }
    if (age > STALE_US) {
        ImGui::TextColored(ImVec4(1, 0.55f, 0.25f, 1),
                           "  %s  STALE %.1f s  -- showing the last frame, "
                           "not live", name, age / 1e6);
        return;
    }

    float dci, dcq;
    {
        std::lock_guard<std::mutex> lk(g_env_mtx[idx]);
        dci = g_env[idx].dc_i;
        dcq = g_env[idx].dc_q;
    }

    if (g_measure_dc.load())
        ImGui::Text("  %s  %u/640 cells    DC  I=%+.0f  Q=%+.0f counts "
                    "(%.2f%% FS)",
                    name, g_cells[idx].load(), dci, dcq,
                    100.0 * sqrt((double)dci * dci + (double)dcq * dcq)
                          / FULL_SCALE);
    else
        ImGui::Text("  %s  %u/640 cells", name, g_cells[idx].load());
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
    GLFWwindow *window = glfwCreateWindow(1400, 860,
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

        uint64_t now    = now_us();
        uint32_t drop   = g_drop.load(), ifdrop = g_ifdrop.load();
        bool stale_dl   = (g_last_us[1].load() == 0) ||
                          (now - g_last_us[1].load() > STALE_US);
        bool stale_ul   = (g_last_us[0].load() == 0) ||
                          (now - g_last_us[0].load() > STALE_US);

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

        lane_status("DL", 1, now);
        lane_status("UL", 0, now);

        ImGui::Checkbox("persistence", &g_persist);
        ImGui::SameLine();
        if (ImGui::Button("clear")) { g_reset[0].store(true); g_reset[1].store(true); }
        ImGui::SameLine();
        ImGui::Checkbox("auto range each channel", &g_autofit);
        ImGui::SameLine();
        ImGui::SetNextItemWidth(200);
        ImGui::SliderFloat("afterglow", &g_afterglow, 0.0f, 20.0f,
                           g_afterglow < 0.01f ? "hold" : "%.1f s");
        ImGui::SameLine();
        bool dc = g_measure_dc.load();
        if (ImGui::Checkbox("measure DC", &dc)) g_measure_dc.store(dc);

        if (ImPlot::BeginSubplots("##stack", 2, 1, ImVec2(-1, -1),
                                  ImPlotSubplotFlags_LinkCols)) {
            draw_trace("DL   gNB -> UE", 1, COL_DL, false, stale_dl);
            draw_trace("UL   UE -> gNB", 0, COL_UL, true,  stale_ul);
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
