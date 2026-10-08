/* -------------------------------------------------------------------------
 * Split 8 fronthaul scope
 *
 * X axis is the slot number, 0 to 19, fixed. Y axis is power in dBFS.
 * Both directions are drawn on the same axes: flat at the noise floor,
 * stepping up in the slots that carry energy. This is the terminal table
 * drawn as a trace.
 *
 * Run:  ./build/src/imgui_app <iface> <dl-src-mac>
 *       sudo setcap "cap_net_raw,cap_net_admin=eip" ./build/src/imgui_app
 *       (setcap must be repeated after every rebuild; do NOT use sudo to
 *        run, it discards the X authority cookie)
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
#define SAMPLES_PER_SLOT  61440
#define FULL_SCALE        32767.0
#define FLOOR_DB          (-125.0f)

static float g_cur_dl[SLOTS_PER_FRAME], g_cur_ul[SLOTS_PER_FRAME];
static float g_pk_dl[SLOTS_PER_FRAME],  g_pk_ul[SLOTS_PER_FRAME];

static std::atomic<uint64_t> g_pkts_dl(0), g_pkts_ul(0);
static std::atomic<uint64_t> g_frames_dl(0), g_frames_ul(0);
static std::atomic<uint32_t> g_cells_dl(0), g_cells_ul(0);
static std::atomic<uint32_t> g_drop(0), g_ifdrop(0);
static std::atomic<uint64_t> g_bad(0), g_trunc(0);
static std::atomic<bool>     g_running(true);
static std::atomic<bool>     g_reset_pk(false);

static pcap_t      *g_ph = NULL;
static unsigned char g_dl_mac[6];

static bool g_show_pk = true;

typedef struct {
    uint64_t acc[SLOTS_PER_FRAME];
    uint8_t  seen[PKTS_PER_FRAME];
    uint32_t last_cell;
    int      started;
    int      is_dl;
} dir_t;

static dir_t g_dl, g_ul;

static void finish_frame(dir_t *d)
{
    float *cur = d->is_dl ? g_cur_dl : g_cur_ul;
    float *pk  = d->is_dl ? g_pk_dl  : g_pk_ul;

    bool clear = g_reset_pk.exchange(false);

    uint32_t have = 0;
    for (uint32_t c = 0; c < PKTS_PER_FRAME; c++) have += d->seen[c];

    for (uint32_t s = 0; s < SLOTS_PER_FRAME; s++) {
        float db = FLOOR_DB;
        if (d->acc[s] > 0) {
            double mean = (double)d->acc[s] / (double)SAMPLES_PER_SLOT;
            db = (float)(10.0 * log10(mean / (FULL_SCALE * FULL_SCALE)));
            if (db < FLOOR_DB) db = FLOOR_DB;
        }
        cur[s] = db;
        if (clear || db > pk[s]) pk[s] = db;
        d->acc[s] = 0;
    }

    memset(d->seen, 0, sizeof d->seen);

    if (d->is_dl) { g_frames_dl++; g_cells_dl.store(have); }
    else          { g_frames_ul++; g_cells_ul.store(have); }
}

/* hot path: each sample touched once, integer arithmetic */
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

    d->acc[cell / PKTS_PER_SLOT] += acc;
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

    for (int s = 0; s < SLOTS_PER_FRAME; s++)
        g_cur_dl[s] = g_cur_ul[s] = g_pk_dl[s] = g_pk_ul[s] = FLOOR_DB;

    /* stairs need one extra point so the last slot is closed off */
    static double xs[SLOTS_PER_FRAME + 1];
    for (int s = 0; s <= SLOTS_PER_FRAME; s++) xs[s] = s;

    static double grid[SLOTS_PER_FRAME + 1];
    for (int s = 0; s <= SLOTS_PER_FRAME; s++) grid[s] = s;

    glfwSetErrorCallback(glfwErrorCallback);
    if (!glfwInit()) { std::cerr << "glfwInit failed\n"; return 1; }

    glfwDefaultWindowHints();
    GLFWwindow *window = glfwCreateWindow(1300, 700,
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

    static double yd[SLOTS_PER_FRAME + 1], yu[SLOTS_PER_FRAME + 1];
    static double qd[SLOTS_PER_FRAME + 1], qu[SLOTS_PER_FRAME + 1];

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

        ImGui::Checkbox("peak hold", &g_show_pk);
        ImGui::SameLine();
        if (ImGui::Button("reset peak")) g_reset_pk.store(true);

        for (int s = 0; s < SLOTS_PER_FRAME; s++) {
            yd[s] = g_cur_dl[s];  yu[s] = g_cur_ul[s];
            qd[s] = g_pk_dl[s];   qu[s] = g_pk_ul[s];
        }
        yd[SLOTS_PER_FRAME] = yd[SLOTS_PER_FRAME - 1];
        yu[SLOTS_PER_FRAME] = yu[SLOTS_PER_FRAME - 1];
        qd[SLOTS_PER_FRAME] = qd[SLOTS_PER_FRAME - 1];
        qu[SLOTS_PER_FRAME] = qu[SLOTS_PER_FRAME - 1];

        if (ImPlot::BeginPlot("##scope", ImVec2(-1, -1))) {
            ImPlot::SetupAxes("slot", "power  (dBFS)");
            ImPlot::SetupAxisLimits(ImAxis_X1, 0, SLOTS_PER_FRAME, ImPlotCond_Always);
            ImPlot::SetupAxisLimits(ImAxis_Y1, -130, 0, ImPlotCond_Always);
            ImPlot::SetupAxisFormat(ImAxis_X1, "%g");

            /* slot boundaries */
            ImPlot::SetNextLineStyle(ImVec4(0.40f, 0.40f, 0.40f, 0.45f), 1.0f);
            ImPlot::PlotInfLines("##grid", grid, SLOTS_PER_FRAME + 1);

            if (g_show_pk) {
                ImPlot::SetNextLineStyle(ImVec4(1.00f, 0.90f, 0.20f, 0.40f), 1.0f);
                ImPlot::PlotStairs("DL peak", xs, qd, SLOTS_PER_FRAME + 1);
                ImPlot::SetNextLineStyle(ImVec4(0.30f, 1.00f, 0.40f, 0.40f), 1.0f);
                ImPlot::PlotStairs("UL peak", xs, qu, SLOTS_PER_FRAME + 1);
            }

            ImPlot::SetNextLineStyle(ImVec4(1.00f, 0.90f, 0.20f, 1.0f), 2.5f);
            ImPlot::PlotStairs("DL  gNB -> UE", xs, yd, SLOTS_PER_FRAME + 1);

            ImPlot::SetNextLineStyle(ImVec4(0.30f, 1.00f, 0.40f, 1.0f), 2.5f);
            ImPlot::PlotStairs("UL  UE -> gNB", xs, yu, SLOTS_PER_FRAME + 1);

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
