/* -------------------------------------------------------------------------
 * Split 8 fronthaul scope - one lane per source MAC
 *
 * Draws what a digital oscilloscope draws: a min/max envelope of the raw
 * waveform, in linear amplitude, about a true zero baseline. For each
 * eCPRI packet (1920 samples) the smallest and largest I sample are kept
 * and the band between them is filled - the same decimation a scope does
 * per pixel column.
 *
 * Why this exists
 *
 *   gui and gui2 split the capture into two lanes by asking one question:
 *
 *       int is_dl = (memcmp(bytes + 6, g_dl_mac, 6) == 0);
 *       dir_t *d  = is_dl ? &g_dl : &g_ul;
 *
 *   Downlink is "from the gNB", uplink is "everything else". That is only
 *   true while exactly two devices sit on the mirror. Put a second gNB on
 *   it - an FPGA transmitting at the same time as the software gNB - and
 *   its downlink is classified as uplink. Two seq_id sequences then
 *   interleave in one accumulator:
 *
 *       device A:  300, 301, 302 ...
 *       device B:    1,   2,   3 ...
 *       as seen:   300,   1, 301,   2, 302,   3 ...
 *
 *   Every other packet steps backwards, the frame is cut almost at once,
 *   and the lane reports 2 of 640 cells while drop stays at zero. Nothing
 *   was lost; the frame was never assembled.
 *
 *   This version stops inferring. Every distinct source MAC gets its own
 *   lane, its own seq_id sequence and its own trace. Senders are
 *   discovered as they appear, so three transmitters show as three traces
 *   without being told anything in advance. What was previously an
 *   asymmetric mystery is now visible on the face of the display.
 *
 * Run
 *
 *   ./build/src/split_scope3 <iface> [mac=label ...]
 *   sudo setcap "cap_net_raw,cap_net_admin=eip" ./build/src/split_scope3
 *
 *   No space after the comma in setcap. The capability is lost on every
 *   rebuild. Do NOT start it with sudo: sudo discards the X authority
 *   cookie and the window will not open.
 *
 *   Naming is optional and only affects presentation - a named MAC gets a
 *   fixed lane position, a fixed colour and a readable label instead of
 *   being ordered by whichever packet happened to arrive first.
 *
 *       ./run.sh sfp1 \
 *           bc:24:11:ec:73:d3=gNB-wnbox4 \
 *           bc:24:11:aa:bb:cc=UE-wnbox7  \
 *           00:0a:35:11:22:33=FPGA-gNB
 * ---------------------------------------------------------------------- */

#include <iostream>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <cmath>
#include <thread>
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

#define MAX_LANES         6

/* A real frame wrap goes 639 -> 0. A reordering of two packets goes 7 -> 6,
   which is also a backward step - treating that as a wrap cuts the frame
   after a couple of packets and collapses the cell count. Only a large
   backward jump is a wrap. */
#define WRAP_MIN          (PKTS_PER_FRAME / 2)

/* ------------------------------------------------------------------ lanes */

typedef struct {
    unsigned char mac[6];
    char          label[24];
    int           named;          /* given on the command line */

    /* capture-thread state */
    int16_t  mn[PKTS_PER_FRAME];
    int16_t  mx[PKTS_PER_FRAME];
    uint8_t  seen[PKTS_PER_FRAME];
    uint32_t last_cell;
    int      started;

    /* live envelope, normalised to +/-1 full scale */
    float lo[PKTS_PER_FRAME],  hi[PKTS_PER_FRAME];

    /* persistence: widest envelope seen since the last clear */
    float plo[PKTS_PER_FRAME], phi[PKTS_PER_FRAME];

    std::atomic<uint32_t> cells;
    std::atomic<uint64_t> pkts;
    std::atomic<uint64_t> pps;
    std::atomic<bool>     reset;

    char title[72];
} lane_t;

static lane_t g_lane[MAX_LANES];

/* Lanes are only ever appended, by the capture thread, and a lane's mac and
   label never change once it exists. The render thread reads g_nlanes and
   then touches only lanes below that index, so publishing the count last is
   enough to make a new lane safe to read. */
static std::atomic<int>      g_nlanes(0);
static std::atomic<uint64_t> g_overflow(0);   /* senders beyond MAX_LANES */

static std::atomic<uint32_t> g_drop(0), g_ifdrop(0);
static std::atomic<uint64_t> g_bad(0), g_trunc(0);
static std::atomic<bool>     g_running(true);

static pcap_t *g_ph = NULL;

static bool g_persist = true;
static bool g_autofit = true;

static void lane_title(lane_t *L, int idx)
{
    char mac[20];
    snprintf(mac, sizeof mac, "%02x:%02x:%02x:%02x:%02x:%02x",
             L->mac[0], L->mac[1], L->mac[2], L->mac[3], L->mac[4], L->mac[5]);

    if (L->label[0])
        snprintf(L->title, sizeof L->title, "%s   src %s", L->label, mac);
    else
        snprintf(L->title, sizeof L->title, "src %s   (lane %d)", mac, idx);
}

/* capture thread only */
static lane_t *lane_for(const unsigned char *src)
{
    int n = g_nlanes.load(std::memory_order_relaxed);

    for (int i = 0; i < n; i++)
        if (memcmp(g_lane[i].mac, src, 6) == 0) return &g_lane[i];

    if (n >= MAX_LANES) { g_overflow++; return NULL; }

    lane_t *L = &g_lane[n];
    memcpy(L->mac, src, 6);
    lane_title(L, n);
    g_nlanes.store(n + 1, std::memory_order_release);   /* publish last */
    return L;
}

static void finish_frame(lane_t *L)
{
    bool clear = L->reset.exchange(false);

    uint32_t have = 0;
    for (uint32_t c = 0; c < PKTS_PER_FRAME; c++) {
        have += L->seen[c];

        float a = (float)(L->mn[c] / FULL_SCALE);
        float b = (float)(L->mx[c] / FULL_SCALE);
        L->lo[c] = a;
        L->hi[c] = b;

        if (clear) { L->plo[c] = a; L->phi[c] = b; }
        else {
            if (a < L->plo[c]) L->plo[c] = a;
            if (b > L->phi[c]) L->phi[c] = b;
        }

        L->mn[c] = 0;
        L->mx[c] = 0;
    }

    memset(L->seen, 0, sizeof L->seen);
    L->cells.store(have);
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

    /* the source address alone decides the lane - no inference about which
       end of the link a sender is on, so a second transmitter cannot land
       in someone else's sequence */
    lane_t *L = lane_for(bytes + 6);
    if (!L) return;

    L->pkts.fetch_add(1, std::memory_order_relaxed);

    /* only a large backward jump is a frame wrap; a small one is a
       reordering and must not split the frame in two */
    if (L->started && cell < L->last_cell &&
        L->last_cell - cell > WRAP_MIN) finish_frame(L);
    L->started   = 1;
    L->last_cell = cell;

    const int16_t *iq = (const int16_t *)(b + ECPRI_HDR_SIZE);

    int16_t mn = 0, mx = 0;
    for (int i = 0; i < SAMPLES_PER_PKT; i++) {
        int16_t I = iq[2 * i];
        if (I < mn) mn = I;
        if (I > mx) mx = I;
    }

    L->mn[cell]   = mn;
    L->mx[cell]   = mx;
    L->seen[cell] = 1;
}

static void stats_thread()
{
    struct pcap_stat st;
    uint32_t pd = 0, pi = 0;
    uint64_t prev[MAX_LANES] = {0};

    while (g_running.load()) {
        std::this_thread::sleep_for(std::chrono::seconds(1));

        if (g_ph && pcap_stats(g_ph, &st) == 0) {
            g_drop.store(st.ps_drop - pd);
            g_ifdrop.store(st.ps_ifdrop - pi);
            pd = st.ps_drop;
            pi = st.ps_ifdrop;
        }

        int n = g_nlanes.load(std::memory_order_acquire);
        for (int i = 0; i < n; i++) {
            uint64_t now = g_lane[i].pkts.load(std::memory_order_relaxed);
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

/* ----------------------------------------------------------------- drawing */

static double g_xs[PKTS_PER_FRAME];
static double g_grid[SLOTS_PER_FRAME + 1];
static double g_lo[PKTS_PER_FRAME], g_hi[PKTS_PER_FRAME];
static double g_plo[PKTS_PER_FRAME], g_phi[PKTS_PER_FRAME];
static double g_mid[PKTS_PER_FRAME];

static double      g_tick_pos[SLOTS_PER_FRAME];
static char        g_tick_buf[SLOTS_PER_FRAME][4];
static const char *g_tick_lbl[SLOTS_PER_FRAME];

static void draw_lane(lane_t *L, ImVec4 col, bool show_x)
{
    double span = 1e-6;
    for (int c = 0; c < PKTS_PER_FRAME; c++) {
        g_lo[c]  = L->lo[c];   g_hi[c]  = L->hi[c];
        g_plo[c] = L->plo[c];  g_phi[c] = L->phi[c];

        /* the scale must follow what is actually drawn. Deriving it from
           the persistence arrays alone meant that clearing them collapsed
           the axis to the 1e-6 seed and the live trace fell outside it. */
        if (fabs(g_hi[c]) > span) span = fabs(g_hi[c]);
        if (fabs(g_lo[c]) > span) span = fabs(g_lo[c]);
        if (g_persist) {
            if (fabs(g_phi[c]) > span) span = fabs(g_phi[c]);
            if (fabs(g_plo[c]) > span) span = fabs(g_plo[c]);
        }
    }
    if (span < 1e-4) span = 1e-4;        /* floor, so it can never collapse */
    span *= 1.15;

    ImPlotAxisFlags xf = ImPlotAxisFlags_Lock;
    if (!show_x) xf |= ImPlotAxisFlags_NoTickLabels;

    if (ImPlot::BeginPlot(L->title, ImVec2(-1, -1), ImPlotFlags_NoLegend)) {
        ImPlot::SetupAxes(show_x ? "slot" : NULL, "amplitude",
                          xf, ImPlotAxisFlags_Lock);
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

static int parse_mac(const char *s, unsigned char out[6])
{
    unsigned int m[6];
    if (sscanf(s, "%x:%x:%x:%x:%x:%x",
               &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]) != 6) return 0;
    for (int i = 0; i < 6; i++) out[i] = (unsigned char)m[i];
    return 1;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        std::cerr
            << "usage: " << argv[0] << " <iface> [mac=label ...]\n"
               "\n"
               "  Every distinct source MAC sending eCPRI gets its own lane,\n"
               "  discovered as it appears. Naming is optional and only fixes\n"
               "  a sender's lane position, colour and label.\n"
               "\n"
               "  e.g. " << argv[0] << " sfp1 \\\n"
               "         bc:24:11:ec:73:d3=gNB-wnbox4 \\\n"
               "         bc:24:11:aa:bb:cc=UE-wnbox7 \\\n"
               "         00:0a:35:11:22:33=FPGA-gNB\n";
        return 1;
    }

    /* g_lane has static storage, so it is already zeroed. Do not memset it:
       lane_t holds std::atomic members and memset over those is not
       something the standard defines. */

    /* pre-register the named senders so their lanes are stable across runs
       rather than ordered by whichever packet arrived first */
    int n = 0;
    for (int a = 2; a < argc && n < MAX_LANES; a++) {
        char macs[64], *eq = strchr(argv[a], '=');
        const char *label = "";

        size_t len = eq ? (size_t)(eq - argv[a]) : strlen(argv[a]);
        if (len >= sizeof macs) { std::cerr << "bad argument: " << argv[a] << "\n"; return 1; }
        memcpy(macs, argv[a], len);
        macs[len] = 0;
        if (eq) label = eq + 1;

        if (!parse_mac(macs, g_lane[n].mac)) {
            std::cerr << "bad MAC: " << macs << "\n";
            return 1;
        }
        snprintf(g_lane[n].label, sizeof g_lane[n].label, "%s", label);
        g_lane[n].named = 1;
        lane_title(&g_lane[n], n);
        n++;
    }
    g_nlanes.store(n);

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
    GLFWwindow *window = glfwCreateWindow(1400, 900,
                                          "Split 8 fronthaul scope - per source",
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

        int      lanes  = g_nlanes.load(std::memory_order_acquire);
        uint32_t drop   = g_drop.load(), ifdrop = g_ifdrop.load();

        ImGui::Text("%s   %d sender%s", argv[1], lanes, lanes == 1 ? "" : "s");

        if (drop || ifdrop)
            ImGui::TextColored(ImVec4(1, 0.25f, 0.25f, 1),
                               "LOSSY  drop=+%u ifdrop=+%u   -- traces have holes",
                               drop, ifdrop);
        else
            ImGui::TextColored(ImVec4(0.3f, 1, 0.3f, 1), "clean  drop=0 ifdrop=0");

        /* drop and ifdrop are blind to loss inside the switch. If the sum of
           the senders' rates approaches the mirror port's line rate, cells
           can sit below 640 on a capture that calls itself clean. */
        uint64_t total_pps = 0;
        for (int i = 0; i < lanes; i++) total_pps += g_lane[i].pps.load();
        double gbps = (double)total_pps * 7702.0 * 8.0 / 1e9;

        ImGui::Text("%llu pkt/s   %.2f Gbit/s on the mirror   bad=%llu trunc=%llu",
                    (unsigned long long)total_pps, gbps,
                    (unsigned long long)g_bad.load(),
                    (unsigned long long)g_trunc.load());

        for (int i = 0; i < lanes; i++) {
            uint32_t cells = g_lane[i].cells.load();
            ImGui::TextColored(COL[i % MAX_LANES],
                               "  %-28s %3u/640 cells   %llu pkt/s%s",
                               g_lane[i].title, cells,
                               (unsigned long long)g_lane[i].pps.load(),
                               cells == 0 ? "   (silent)" : "");
        }

        uint64_t ovf = g_overflow.load();
        if (ovf)
            ImGui::TextColored(ImVec4(1, 0.8f, 0.3f, 1),
                               "  more than %d senders - %llu packets ignored",
                               MAX_LANES, (unsigned long long)ovf);

        ImGui::Checkbox("persistence", &g_persist);
        ImGui::SameLine();
        if (ImGui::Button("clear"))
            for (int i = 0; i < lanes; i++) g_lane[i].reset.store(true);
        ImGui::SameLine();
        ImGui::Checkbox("auto range each lane", &g_autofit);

        if (lanes == 0) {
            ImGui::Dummy(ImVec2(0, 20));
            ImGui::TextColored(ImVec4(1, 0.8f, 0.3f, 1),
                               "no eCPRI frames yet.");
            ImGui::TextWrapped(
                "Check the interface is up, promiscuous and has an MTU of "
                "9000, and that the mirror is actually carrying 0xAEFE "
                "frames:  sudo tcpdump -i %s -nn -e -c 5 'ether proto 0xaefe'",
                argv[1]);
        } else if (ImPlot::BeginSubplots("##stack", lanes, 1, ImVec2(-1, -1),
                                         ImPlotSubplotFlags_LinkCols)) {
            for (int i = 0; i < lanes; i++)
                draw_lane(&g_lane[i], COL[i % MAX_LANES], i == lanes - 1);
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
