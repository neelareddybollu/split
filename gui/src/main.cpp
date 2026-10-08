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

/* live envelope, normalised to +/-1 full scale */
static float g_dl_lo[PKTS_PER_FRAME], g_dl_hi[PKTS_PER_FRAME];
static float g_ul_lo[PKTS_PER_FRAME], g_ul_hi[PKTS_PER_FRAME];

/* persistence: widest envelope ever seen */
static float g_dl_plo[PKTS_PER_FRAME], g_dl_phi[PKTS_PER_FRAME];
static float g_ul_plo[PKTS_PER_FRAME], g_ul_phi[PKTS_PER_FRAME];

static std::atomic<uint32_t> g_cells_dl(0), g_cells_ul(0);
static std::atomic<uint32_t> g_drop(0), g_ifdrop(0);
static std::atomic<uint64_t> g_bad(0), g_trunc(0);
static std::atomic<bool>     g_running(true);
static std::atomic<bool>     g_reset_pk(false);

static pcap_t      *g_ph = NULL;
static unsigned char g_dl_mac[6];

static bool g_persist = true;
static bool g_autofit = true;

typedef struct {
    int16_t  mn[PKTS_PER_FRAME];
    int16_t  mx[PKTS_PER_FRAME];
    uint8_t  seen[PKTS_PER_FRAME];
    uint32_t last_cell;
    int      started;
    int      is_dl;
} dir_t;

static dir_t g_dl, g_ul;

static void finish_frame(dir_t *d)
{
    float *lo  = d->is_dl ? g_dl_lo  : g_ul_lo;
    float *hi  = d->is_dl ? g_dl_hi  : g_ul_hi;
    float *plo = d->is_dl ? g_dl_plo : g_ul_plo;
    float *phi = d->is_dl ? g_dl_phi : g_ul_phi;

    bool clear = g_reset_pk.exchange(false);

    uint32_t have = 0;
    for (uint32_t c = 0; c < PKTS_PER_FRAME; c++) {
        have += d->seen[c];

        float a = (float)(d->mn[c] / FULL_SCALE);
        float b = (float)(d->mx[c] / FULL_SCALE);
        lo[c] = a;
        hi[c] = b;

        if (clear) { plo[c] = a; phi[c] = b; }
        else {
            if (a < plo[c]) plo[c] = a;
            if (b > phi[c]) phi[c] = b;
        }

        d->mn[c] = 0;
        d->mx[c] = 0;
    }

    memset(d->seen, 0, sizeof d->seen);

    if (d->is_dl) g_cells_dl.store(have);
    else          g_cells_ul.store(have);
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

    if (d->started && cell < d->last_cell) finish_frame(d);
    d->started   = 1;
    d->last_cell = cell;

    const int16_t *iq = (const int16_t *)(b + ECPRI_HDR_SIZE);

    int16_t mn = 0, mx = 0;
    for (int i = 0; i < SAMPLES_PER_PKT; i++) {
        int16_t I = iq[2 * i];
        if (I < mn) mn = I;
        if (I > mx) mx = I;
    }

    d->mn[cell] = mn;
    d->mx[cell] = mx;
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

static double      g_tick_pos[SLOTS_PER_FRAME];
static char        g_tick_buf[SLOTS_PER_FRAME][4];
static const char *g_tick_lbl[SLOTS_PER_FRAME];

static void draw_trace(const char *title,
                       const float *lo,  const float *hi,
                       const float *plo, const float *phi,
                       ImVec4 col, bool show_x)
{
    double span = 1e-6;
    for (int c = 0; c < PKTS_PER_FRAME; c++) {
        g_lo[c]  = lo[c];   g_hi[c]  = hi[c];
        g_plo[c] = plo[c];  g_phi[c] = phi[c];
        if (fabs(g_phi[c]) > span) span = fabs(g_phi[c]);
        if (fabs(g_plo[c]) > span) span = fabs(g_plo[c]);
    }
    span *= 1.15;

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
    g_dl.is_dl = 1;

    for (int c = 0; c < PKTS_PER_FRAME; c++) {
        g_dl_lo[c] = g_dl_hi[c] = g_ul_lo[c] = g_ul_hi[c] = 0.0f;
        g_dl_plo[c] = g_dl_phi[c] = g_ul_plo[c] = g_ul_phi[c] = 0.0f;
        g_xs[c] = (double)c / (double)PKTS_PER_SLOT;   /* x in slot units */
    }
    for (int s = 0; s <= SLOTS_PER_FRAME; s++) g_grid[s] = s;
    for (int s = 0; s < SLOTS_PER_FRAME; s++) {
        g_tick_pos[s] = s + 0.5;
        snprintf(g_tick_buf[s], sizeof g_tick_buf[s], "%d", s);
        g_tick_lbl[s] = g_tick_buf[s];
    }

    glfwSetErrorCallback(glfwErrorCallback);
    if (!glfwInit()) { std::cerr << "glfwInit failed\n"; return 1; }

    glfwDefaultWindowHints();
    GLFWwindow *window = glfwCreateWindow(1400, 820,
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

        uint32_t drop = g_drop.load(), ifdrop = g_ifdrop.load();

        ImGui::Text("%s   DL src %s   |   %u/640 cells DL   %u/640 cells UL",
                    argv[1], argv[2], g_cells_dl.load(), g_cells_ul.load());

        if (drop || ifdrop)
            ImGui::TextColored(ImVec4(1, 0.25f, 0.25f, 1),
                               "LOSSY  drop=+%u ifdrop=+%u   -- trace has holes",
                               drop, ifdrop);
        else
            ImGui::TextColored(ImVec4(0.3f, 1, 0.3f, 1), "clean  drop=0 ifdrop=0");

        ImGui::Checkbox("persistence", &g_persist);
        ImGui::SameLine();
        if (ImGui::Button("clear")) g_reset_pk.store(true);
        ImGui::SameLine();
        ImGui::Checkbox("auto range each channel", &g_autofit);

        if (ImPlot::BeginSubplots("##stack", 2, 1, ImVec2(-1, -1),
                                  ImPlotSubplotFlags_LinkCols)) {
            draw_trace("DL   gNB -> UE", g_dl_lo, g_dl_hi, g_dl_plo, g_dl_phi,
                       COL_DL, false);
            draw_trace("UL   UE -> gNB", g_ul_lo, g_ul_hi, g_ul_plo, g_ul_phi,
                       COL_UL, true);
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
