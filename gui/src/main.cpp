/* -------------------------------------------------------------------------
 * Split 8 fronthaul scope - ImGui / ImPlot front end
 *
 * Captures eCPRI frames from a switch mirror port, separates the two
 * directions by source MAC, accumulates per-slot energy, and draws a
 * scrolling waterfall for each direction.
 *
 * Capture runs on its own thread. The render thread only ever reads the
 * shared waterfall arrays - it must never block the capture path, or the
 * kernel buffer overflows and packets are lost.
 *
 * Build: this file replaces src/main.cpp in the imgui_mini skeleton.
 *        src/CMakeLists.txt must link pcap, m and pthread.
 *
 * Run:   sudo ./build/src/imgui_app <iface> <dl-src-mac>
 * e.g.   sudo ./build/src/imgui_app sfp1 bc:24:11:ec:73:d3
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

/* ---- fronthaul geometry (mu = 1, 122.88 Msps) ------------------------- */

#define ECPRI_HDR_SIZE    8
#define SAMPLES_PER_PKT   1920
#define PKTS_PER_SLOT     32
#define SLOTS_PER_FRAME   20
#define PKTS_PER_FRAME    640
#define SAMPLES_PER_SLOT  61440
#define FULL_SCALE        32767.0
#define ETH_ECPRI         0xAEFE

#define HIST              400      /* waterfall rows = 4 seconds of frames */
#define SILENT_DB         (-120.0f)

/* ---- shared state ----------------------------------------------------- */

static float g_wf_dl[HIST][SLOTS_PER_FRAME];
static float g_wf_ul[HIST][SLOTS_PER_FRAME];

static std::atomic<int>      g_row_dl(0), g_row_ul(0);
static std::atomic<uint64_t> g_pkts_dl(0), g_pkts_ul(0);
static std::atomic<uint64_t> g_frames_dl(0), g_frames_ul(0);
static std::atomic<uint32_t> g_cells_dl(0), g_cells_ul(0);
static std::atomic<uint32_t> g_drop(0), g_ifdrop(0);
static std::atomic<uint64_t> g_bad(0), g_trunc(0);
static std::atomic<bool>     g_running(true);

static pcap_t      *g_ph = NULL;
static unsigned char g_dl_mac[6];

/* ---- per-direction accumulator ---------------------------------------- */

typedef struct {
    uint64_t acc[SLOTS_PER_FRAME];   /* running sum of I^2 + Q^2 */
    uint8_t  seen[PKTS_PER_FRAME];
    uint32_t last_cell;
    int      started;
    int      is_dl;
} dir_t;

static dir_t g_dl, g_ul;

static void print_terminal_block(void);   /* defined below */

static void finish_frame(dir_t *d)
{
    float (*wf)[SLOTS_PER_FRAME] = d->is_dl ? g_wf_dl : g_wf_ul;
    std::atomic<int> &rowref     = d->is_dl ? g_row_dl : g_row_ul;

    uint32_t have = 0;
    for (uint32_t c = 0; c < PKTS_PER_FRAME; c++) have += d->seen[c];

    int row = rowref.load();

    for (uint32_t s = 0; s < SLOTS_PER_FRAME; s++) {
        float db = SILENT_DB;
        if (d->acc[s] > 0) {
            double mean = (double)d->acc[s] / (double)SAMPLES_PER_SLOT;
            db = (float)(10.0 * log10(mean / (FULL_SCALE * FULL_SCALE)));
        }
        wf[row][s] = db;
        d->acc[s]  = 0;
    }

    rowref.store((row + 1) % HIST);
    memset(d->seen, 0, sizeof d->seen);

    if (d->is_dl) { g_frames_dl++; g_cells_dl.store(have); }
    else          { g_frames_ul++; g_cells_ul.store(have); }
}

/* ---- capture callback -------------------------------------------------
 * Hot path. Touches each sample exactly once, straight out of the
 * capture buffer, with integer arithmetic. No frame buffer, no memset.
 * -------------------------------------------------------------------- */

static void on_packet(unsigned char *user, const struct pcap_pkthdr *h,
                      const unsigned char *bytes)
{
    (void)user;

    if (h->caplen < 14 + ECPRI_HDR_SIZE + SAMPLES_PER_PKT * 4) {
        g_trunc++;
        return;
    }

    const unsigned char *b = bytes + 14;          /* skip Ethernet header */

    if (((b[0] >> 4) & 0x0F) != 1 || b[1] != 0x00) { g_bad++; return; }

    uint16_t v;
    memcpy(&v, b + 6, 2);
    uint16_t seq = ntohs(v);
    if (seq < 1 || seq > PKTS_PER_FRAME) { g_bad++; return; }

    uint32_t cell = (uint32_t)seq - 1;

    int is_dl = (memcmp(bytes + 6, g_dl_mac, 6) == 0);
    dir_t *d  = is_dl ? &g_dl : &g_ul;

    if (is_dl) g_pkts_dl++; else g_pkts_ul++;

    /* a cell number that went backwards means a new frame started */
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
    uint32_t prev_drop = 0, prev_ifdrop = 0;
    while (g_running.load()) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        if (g_ph && pcap_stats(g_ph, &st) == 0) {
            g_drop.store(st.ps_drop   - prev_drop);
            g_ifdrop.store(st.ps_ifdrop - prev_ifdrop);
            prev_drop   = st.ps_drop;
            prev_ifdrop = st.ps_ifdrop;
        }
        print_terminal_block();
    }
}

static void capture_thread(const char *iface)
{
    char err[PCAP_ERRBUF_SIZE] = {0};

    g_ph = pcap_create(iface, err);
    if (!g_ph) { std::cerr << "pcap_create: " << err << "\n"; return; }

    /* buffer size must be set BEFORE activation */
    pcap_set_snaplen(g_ph, 9000);
    pcap_set_promisc(g_ph, 1);
    pcap_set_timeout(g_ph, 10);
    pcap_set_buffer_size(g_ph, 256 * 1024 * 1024);

    int rc = pcap_activate(g_ph);
    if (rc < 0) {
        std::cerr << "pcap_activate: " << pcap_geterr(g_ph) << "\n";
        return;
    }

    struct bpf_program fp;
    if (pcap_compile(g_ph, &fp, "ether proto 0xaefe", 1,
                     PCAP_NETMASK_UNKNOWN) == 0) {
        pcap_setfilter(g_ph, &fp);
        pcap_freecode(&fp);
    } else {
        std::cerr << "filter: " << pcap_geterr(g_ph) << "\n";
    }

    pcap_loop(g_ph, -1, on_packet, NULL);
}

/* ---- drawing ---------------------------------------------------------- */

static void draw_waterfall(const char *title, float wf[HIST][SLOTS_PER_FRAME],
                           std::atomic<int> &rowref)
{
    static float snap[HIST * SLOTS_PER_FRAME];

    int head = rowref.load();
    for (int r = 0; r < HIST; r++) {
        int src = (head + r) % HIST;              /* oldest row first */
        memcpy(&snap[r * SLOTS_PER_FRAME], wf[src],
               SLOTS_PER_FRAME * sizeof(float));
    }

    if (ImPlot::BeginPlot(title, ImVec2(-1, 320))) {
        ImPlot::SetupAxes("slot", "frames ago",
                          ImPlotAxisFlags_Lock, ImPlotAxisFlags_Lock);
        ImPlot::SetupAxisLimits(ImAxis_X1, 0, SLOTS_PER_FRAME);
        ImPlot::SetupAxisLimits(ImAxis_Y1, 0, HIST);
        ImPlot::PlotHeatmap("##hm", snap, HIST, SLOTS_PER_FRAME,
                            -90.0, 0.0, NULL,
                            ImPlotPoint(0, 0),
                            ImPlotPoint(SLOTS_PER_FRAME, HIST));
        ImPlot::EndPlot();
    }
}

/* latest completed row for a direction */
static int latest_row(std::atomic<int> &rowref)
{
    return (rowref.load() + HIST - 1) % HIST;
}

/* the same per-slot numbers live2 prints, as a table inside the window */
static void draw_slot_table()
{
    int rd = latest_row(g_row_dl);
    int ru = latest_row(g_row_ul);

    if (ImGui::BeginTable("slots", 3,
                          ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
                          ImGuiTableFlags_SizingFixedFit)) {
        ImGui::TableSetupColumn("slot");
        ImGui::TableSetupColumn("DL (gNB -> UE)");
        ImGui::TableSetupColumn("UL (UE -> gNB)");
        ImGui::TableHeadersRow();

        for (int s = 0; s < SLOTS_PER_FRAME; s++) {
            float dl = g_wf_dl[rd][s];
            float ul = g_wf_ul[ru][s];
            if (dl <= SILENT_DB && ul <= SILENT_DB) continue;   /* hide silence */

            ImGui::TableNextRow();
            ImGui::TableNextColumn(); ImGui::Text("%d", s);
            ImGui::TableNextColumn();
            if (dl > SILENT_DB) ImGui::Text("%.1f", dl); else ImGui::TextDisabled("-");
            ImGui::TableNextColumn();
            if (ul > SILENT_DB) ImGui::Text("%.1f", ul); else ImGui::TextDisabled("-");
        }
        ImGui::EndTable();
    }
}

/* the live2 terminal block, printed from this same process */
static void print_terminal_block()
{
    int rd = latest_row(g_row_dl);
    int ru = latest_row(g_row_ul);

    uint32_t drop = g_drop.load(), ifdrop = g_ifdrop.load();

    printf("\033[H\033[J");
    printf("Split 8 fronthaul  |  DL %llu pkts %llu frames %u/640 cells"
           "  |  UL %llu pkts %llu frames %u/640 cells\n",
           (unsigned long long)g_pkts_dl.load(),
           (unsigned long long)g_frames_dl.load(), g_cells_dl.load(),
           (unsigned long long)g_pkts_ul.load(),
           (unsigned long long)g_frames_ul.load(), g_cells_ul.load());
    printf("capture: drop=+%u ifdrop=+%u  bad=%llu trunc=%llu   %s\n\n",
           drop, ifdrop,
           (unsigned long long)g_bad.load(),
           (unsigned long long)g_trunc.load(),
           (drop || ifdrop) ? "<< LOSSY" : "clean");

    printf("slot   DL (gNB -> UE)        UL (UE -> gNB)\n");
    for (int s = 0; s < SLOTS_PER_FRAME; s++) {
        float dl = g_wf_dl[rd][s];
        float ul = g_wf_ul[ru][s];
        if (dl <= SILENT_DB && ul <= SILENT_DB) continue;
        printf("  %3d    %6.1f                 %6.1f\n", s, dl, ul);
    }
    fflush(stdout);
}

static void glfwErrorCallback(int error, const char *description)
{
    std::cerr << "GLFW error " << error << ": " << description << '\n';
}

int main(int argc, char **argv)
{
    if (argc < 3) {
        std::cerr << "usage: " << argv[0]
                  << " <iface> <dl-src-mac>\n"
                     "  e.g. " << argv[0]
                  << " sfp1 bc:24:11:ec:73:d3\n";
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

    for (int r = 0; r < HIST; r++)
        for (int s = 0; s < SLOTS_PER_FRAME; s++)
            g_wf_dl[r][s] = g_wf_ul[r][s] = SILENT_DB;

    /* ---- window ------------------------------------------------------ */

    glfwSetErrorCallback(glfwErrorCallback);
    if (!glfwInit()) { std::cerr << "glfwInit failed\n"; return 1; }

    glfwDefaultWindowHints();

    GLFWwindow *window = glfwCreateWindow(1100, 820,
                                          "Split 8 fronthaul scope",
                                          nullptr, nullptr);
    if (!window) {
        std::cerr << "no window - is DISPLAY set?\n";
        glfwTerminate();
        return 1;
    }
    glfwMakeContextCurrent(window);
    glfwSwapInterval(1);

    if (glewInit() != GLEW_OK) { std::cerr << "glewInit failed\n"; return 1; }

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImPlot::CreateContext();
    ImGui::StyleColorsDark();

    ImGuiIO &io = ImGui::GetIO();
    io.ConfigFlags |= ImGuiConfigFlags_DockingEnable;
    /* Viewports deliberately NOT enabled - undocked windows become
     * separate X windows, which is slow and unreliable over ssh -X. */

    ImGui_ImplGlfw_InitForOpenGL(window, true);
    ImGui_ImplOpenGL3_Init("#version 130");

    std::thread cap(capture_thread, argv[1]);
    std::thread sta(stats_thread);

    /* ---- main loop --------------------------------------------------- */

    while (!glfwWindowShouldClose(window)) {
        glfwPollEvents();

        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplGlfw_NewFrame();
        ImGui::NewFrame();

        ImGui::DockSpaceOverViewport(0, ImGui::GetMainViewport());

        ImGui::Begin("Split 8 fronthaul");

        uint32_t drop = g_drop.load(), ifdrop = g_ifdrop.load();

        ImGui::Text("iface %s   DL src %s", argv[1], argv[2]);
        ImGui::Text("DL  %llu pkts  %llu frames  %u/640 cells",
                    (unsigned long long)g_pkts_dl.load(),
                    (unsigned long long)g_frames_dl.load(),
                    g_cells_dl.load());
        ImGui::Text("UL  %llu pkts  %llu frames  %u/640 cells",
                    (unsigned long long)g_pkts_ul.load(),
                    (unsigned long long)g_frames_ul.load(),
                    g_cells_ul.load());

        if (drop || ifdrop)
            ImGui::TextColored(ImVec4(1, 0.3f, 0.3f, 1),
                               "capture: drop=+%u ifdrop=+%u   << LOSSY",
                               drop, ifdrop);
        else
            ImGui::TextColored(ImVec4(0.3f, 1, 0.3f, 1),
                               "capture: drop=+0 ifdrop=+0   clean");

        ImGui::Text("bad=%llu trunc=%llu",
                    (unsigned long long)g_bad.load(),
                    (unsigned long long)g_trunc.load());
        ImGui::Text("%.1f FPS", io.Framerate);

        ImGui::Separator();
        draw_slot_table();

        ImGui::Separator();
        draw_waterfall("downlink  (gNB -> UE)", g_wf_dl, g_row_dl);
        draw_waterfall("uplink    (UE -> gNB)", g_wf_ul, g_row_ul);

        ImGui::End();

        ImGui::Render();
        int w, h;
        glfwGetFramebufferSize(window, &w, &h);
        glViewport(0, 0, w, h);
        glClearColor(0.15f, 0.16f, 0.21f, 1.00f);
        glClear(GL_COLOR_BUFFER_BIT);
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
        glfwSwapBuffers(window);
    }

    /* ---- shutdown ---------------------------------------------------- */

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
