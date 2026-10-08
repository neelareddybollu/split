/* -------------------------------------------------------------------------
 * Split 8 fronthaul scope
 *
 * Oscilloscope layout: one shared time axis, each direction in its own
 * horizontal lane (like C1/C2 on a bench scope). Resolution is one point
 * per eCPRI packet (15.625 us). Span is adjustable from one 10 ms frame
 * up to 32 frames (320 ms).
 *
 * Run:  ./build/src/imgui_app <iface> <dl-src-mac>
 *       sudo setcap "cap_net_raw,cap_net_admin=eip" ./build/src/imgui_app
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
#define FULL_SCALE        32767.0
#define SILENT_DB         (-125.0f)

#define MS_PER_PKT        0.015625        /* 15.625 us */
#define FRAMES_HIST       32              /* ring depth = 320 ms */
#define NPTS              (PKTS_PER_FRAME * FRAMES_HIST)

static float g_hist_dl[NPTS], g_hist_ul[NPTS];
static std::atomic<int> g_fr_dl(0), g_fr_ul(0);   /* next frame slot */

static std::atomic<uint64_t> g_pkts_dl(0), g_pkts_ul(0);
static std::atomic<uint64_t> g_frames_dl(0), g_frames_ul(0);
static std::atomic<uint32_t> g_cells_dl(0), g_cells_ul(0);
static std::atomic<uint32_t> g_drop(0), g_ifdrop(0);
static std::atomic<uint64_t> g_bad(0), g_trunc(0);
static std::atomic<bool>     g_running(true);

static pcap_t      *g_ph = NULL;
static unsigned char g_dl_mac[6];

static int  g_span   = 8;        /* frames shown */
static bool g_frozen = false;

typedef struct {
    uint64_t acc[PKTS_PER_FRAME];
    uint8_t  seen[PKTS_PER_FRAME];
    uint32_t last_cell;
    int      started;
    int      is_dl;
} dir_t;

static dir_t g_dl, g_ul;

static void finish_frame(dir_t *d)
{
    float *hist = d->is_dl ? g_hist_dl : g_hist_ul;
    std::atomic<int> &fr = d->is_dl ? g_fr_dl : g_fr_ul;

    int f = fr.load();
    float *row = hist + (size_t)f * PKTS_PER_FRAME;

    uint32_t have = 0;
    for (uint32_t c = 0; c < PKTS_PER_FRAME; c++) {
        have += d->seen[c];

        float db = SILENT_DB;
        if (d->acc[c] > 0) {
            double mean = (double)d->acc[c] / (double)(SAMPLES_PER_PKT * 2);
            db = (float)(10.0 * log10(mean / (FULL_SCALE * FULL_SCALE)));
            if (db < SILENT_DB) db = SILENT_DB;
        }
        row[c] = db;
        d->acc[c] = 0;
    }

    fr.store((f + 1) % FRAMES_HIST);
    memset(d->seen, 0, sizeof d->seen);

    if (d->is_dl) { g_frames_dl++; g_cells_dl.store(have); }
    else          { g_frames_ul++; g_cells_ul.store(have); }
}

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

    if (is_dl) g_pkts_dl++; else g_pkts_ul++;

    if (d->started && cell < d->last_cell) finish_frame(d);
    d->started   = 1;
    d->last_cell = cell;

    const int16_t *iq = (const int16_t *)(b + ECPRI_HDR_SIZE);
    uint64_t acc = 0;
    for (int i = 0; i < SAMPLES_PER_PKT * 2; i++) {
        int32_t s = iq[i];
        acc += (uint64_t)(s * s);
    }

    d->acc[cell] += acc;
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

/* map dBFS into a lane of height 1.0 starting at base */
static inline double lane(double db, double base)
{
    double v = (db - SILENT_DB) / (0.0 - SILENT_DB);
    if (v < 0) v = 0;
    if (v > 1) v = 1;
    return base + v;
}

static void glfwErrorCallback(int e, const char *d)
{
    std::cerr << "GLFW error " << e << ": " << d << '\n';
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

    for (int i = 0; i < NPTS; i++) g_hist_dl[i] = g_hist_ul[i] = SILENT_DB;

    glfwSetErrorCallback(glfwErrorCallback);
    if (!glfwInit()) { std::cerr << "glfwInit failed\n"; return 1; }

    glfwDefaultWindowHints();
    GLFWwindow *window = glfwCreateWindow(1400, 760,
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

    ImGui_ImplGlfw_InitForOpenGL(window, true);
    ImGui_ImplOpenGL3_Init("#version 130");

    std::thread cap(capture_thread, argv[1]);
    std::thread sta(stats_thread);

    static double xs[NPTS], yd[NPTS], yu[NPTS];
    static double fx[FRAMES_HIST + 1];

    static const double tick_pos[2]  = { 0.5, 1.6 };
    static const char  *tick_lbl[2]  = { "UL   UE -> gNB", "DL   gNB -> UE" };

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

        ImGui::Text("%s   DL src %s   |   DL %llu pkts %llu frames %u/640   |   UL %llu pkts %llu frames %u/640",
                    argv[1], argv[2],
                    (unsigned long long)g_pkts_dl.load(),
                    (unsigned long long)g_frames_dl.load(), g_cells_dl.load(),
                    (unsigned long long)g_pkts_ul.load(),
                    (unsigned long long)g_frames_ul.load(), g_cells_ul.load());

        if (drop || ifdrop)
            ImGui::TextColored(ImVec4(1, 0.3f, 0.3f, 1),
                               "drop=+%u ifdrop=+%u  << LOSSY    %.0f FPS", drop, ifdrop, io.Framerate);
        else
            ImGui::TextColored(ImVec4(0.3f, 1, 0.3f, 1),
                               "drop=+0 ifdrop=+0  clean    %.0f FPS", io.Framerate);

        ImGui::SetNextItemWidth(300);
        ImGui::SliderInt("span (frames of 10 ms)", &g_span, 1, FRAMES_HIST);
        ImGui::SameLine();
        ImGui::Checkbox("freeze", &g_frozen);

        int n = g_span * PKTS_PER_FRAME;

        if (!g_frozen) {
            int fd = g_fr_dl.load();
            int fu = g_fr_ul.load();
            int sd = (fd - g_span + FRAMES_HIST) % FRAMES_HIST;
            int su = (fu - g_span + FRAMES_HIST) % FRAMES_HIST;

            for (int i = 0; i < n; i++) {
                int f  = i / PKTS_PER_FRAME;
                int c  = i % PKTS_PER_FRAME;
                xs[i] = i * MS_PER_PKT;
                yd[i] = lane(g_hist_dl[((sd + f) % FRAMES_HIST) * PKTS_PER_FRAME + c], 1.1);
                yu[i] = lane(g_hist_ul[((su + f) % FRAMES_HIST) * PKTS_PER_FRAME + c], 0.0);
            }
        }

        for (int f = 0; f <= g_span; f++) fx[f] = f * 10.0;

        if (ImPlot::BeginPlot("##scope", ImVec2(-1, -1), ImPlotFlags_NoLegend)) {
            ImPlot::SetupAxes("time  (ms)", NULL);
            ImPlot::SetupAxisLimits(ImAxis_X1, 0, g_span * 10.0, ImPlotCond_Always);
            ImPlot::SetupAxisLimits(ImAxis_Y1, -0.05, 2.25, ImPlotCond_Always);
            ImPlot::SetupAxisTicks(ImAxis_Y1, tick_pos, 2, tick_lbl);

            /* frame boundaries every 10 ms */
            ImPlot::SetNextLineStyle(ImVec4(0.45f, 0.45f, 0.45f, 0.6f), 1.0f);
            ImPlot::PlotInfLines("##frame", fx, g_span + 1);

            ImPlot::SetNextLineStyle(ImVec4(1.00f, 0.90f, 0.20f, 1.0f), 1.3f);
            ImPlot::PlotLine("DL", xs, yd, n);

            ImPlot::SetNextLineStyle(ImVec4(0.30f, 1.00f, 0.40f, 1.0f), 1.3f);
            ImPlot::PlotLine("UL", xs, yu, n);

            ImPlot::EndPlot();
        }

        ImGui::End();

        ImGui::Render();
        int w, h;
        glfwGetFramebufferSize(window, &w, &h);
        glViewport(0, 0, w, h);
        glClearColor(0.05f, 0.05f, 0.07f, 1.00f);
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
