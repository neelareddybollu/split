/* -------------------------------------------------------------------------
 * Split 8 fronthaul scope - ImGui / ImPlot
 *
 * The GUI twin of "live3 -g": one 10 ms radio frame drawn across the window,
 * both directions, at the resolution the fronthaul actually carries - one
 * point per eCPRI packet, 1920 samples, 15.625 us, 640 points per frame.
 *
 * Two stacked plots share the slot axis. Each has its own Y axis because the
 * uplink runs 30-40 dB below the downlink and a shared scale would flatten
 * it. Vertical lines mark the twenty slot boundaries.
 *
 * Capture runs on its own thread and the render thread only reads. At
 * 128,000 packets per second the capture path must never wait on the
 * renderer - the drop counter at the top is the check.
 *
 *   drop=0            the picture is trustworthy
 *   drop non-zero     it is not, and it says so in red
 *
 * Build, inside the imgui_mini skeleton:
 *   bash build.sh
 *   sudo setcap "cap_net_raw,cap_net_admin=eip" ./build/src/imgui_app
 *   ./build/src/imgui_app sfp1 bc:24:11:ec:73:d3
 *
 * Do not run it with sudo - sudo discards the X authority cookie and the
 * window cannot open. setcap once after every rebuild instead.
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

#define ETH_HDR            14
#define ECPRI_HDR_SIZE      8
#define SAMPLES_PER_PKT  1920
#define PKTS_PER_SLOT      32
#define PKTS_PER_FRAME    640
#define SLOTS_PER_FRAME    20
#define IQ_BYTES         7680
#define FULL_SCALE       32767.0
#define SILENT_DB        (-120.0)
#define QUIET_DB         (-110.0)
#define US_PER_PKT       15.625
#define WRAP_MIN         (PKTS_PER_FRAME / 2)

/* This testbed: 5 ms pattern, 7 DL slots, 1 mixed, 2 UL, twice per frame.
   Slots 0-6 and 10-16 can never carry uplink. */
static inline bool is_dl_only(int slot) { return (slot % 10) <= 6; }

/* ---- shared between the two threads ----------------------------------- */

static float g_cur_dl[PKTS_PER_FRAME], g_cur_ul[PKTS_PER_FRAME];
static float g_pk_dl [PKTS_PER_FRAME], g_pk_ul [PKTS_PER_FRAME];

static std::atomic<uint64_t> g_pkts_dl(0), g_pkts_ul(0);
static std::atomic<uint32_t> g_cells_dl(0), g_cells_ul(0);
static std::atomic<uint64_t> g_partial_dl(0), g_partial_ul(0);
static std::atomic<uint32_t> g_drop(0), g_ifdrop(0);
static std::atomic<uint64_t> g_bad(0), g_trunc(0), g_reorder(0);
static std::atomic<bool>     g_running(true);
static std::atomic<bool>     g_clear_peak(false);

static std::atomic<double>   g_skew_us(0.0);
static std::atomic<double>   g_late_dl(0.0), g_late_ul(0.0);

static std::atomic<uint64_t> g_viol_n(0), g_viol_frame(0);
static std::atomic<int>      g_viol_slot(-1);
static std::atomic<double>   g_viol_db(0.0);

static pcap_t      *g_ph = NULL;
static unsigned char g_gnb[6];

/* display options, touched only by the render thread */
static bool g_show_peak = true;
static bool g_autoscale = true;

/* ---- per-direction state ---------------------------------------------- */

typedef struct {
    char      tag;                       /* 'D' or 'U' */
    uint64_t  acc[PKTS_PER_FRAME];
    uint64_t  nsamp[PKTS_PER_FRAME];
    uint8_t   seen[PKTS_PER_FRAME];
    uint32_t  last_cell;
    int       started;
    uint64_t  fno;
    struct timeval t0;
    int       t0_valid;
    double    late_max;
} dir_t;

static dir_t g_dl, g_ul;

static double to_db(uint64_t acc, uint64_t n)
{
    if (n == 0 || acc == 0) return SILENT_DB;
    double db = 10.0 * log10(((double)acc / (double)n)
                             / (FULL_SCALE * FULL_SCALE));
    return db < SILENT_DB ? SILENT_DB : db;
}

static double us_between(const struct timeval *a, const struct timeval *b)
{
    return (double)(b->tv_sec - a->tv_sec) * 1e6
         + (double)(b->tv_usec - a->tv_usec);
}

static void finish_frame(dir_t *d)
{
    bool   is_dl = (d->tag == 'D');
    float *cur   = is_dl ? g_cur_dl : g_cur_ul;
    float *pk    = is_dl ? g_pk_dl  : g_pk_ul;

    bool clear = g_clear_peak.exchange(false);

    uint32_t have = 0;
    for (uint32_t c = 0; c < PKTS_PER_FRAME; c++) have += d->seen[c];

    for (uint32_t s = 0; s < SLOTS_PER_FRAME; s++) {
        uint64_t sacc = 0, sn = 0;

        for (uint32_t k = 0; k < PKTS_PER_SLOT; k++) {
            uint32_t c = s * PKTS_PER_SLOT + k;
            sacc += d->acc[c];
            sn   += d->nsamp[c];

            float db = (float)to_db(d->acc[c], d->nsamp[c]);
            cur[c] = db;
            if (clear || db > pk[c]) pk[c] = db;

            d->acc[c]   = 0;
            d->nsamp[c] = 0;
        }

        /* uplink energy where the TDD pattern forbids it */
        if (!is_dl && is_dl_only((int)s)) {
            double sdb = to_db(sacc, sn);
            if (sdb > QUIET_DB) {
                g_viol_n++;
                g_viol_frame.store(d->fno);
                g_viol_slot.store((int)s);
                g_viol_db.store(sdb);
                fprintf(stderr, "TDD VIOLATION  frame %llu  uplink in DL slot"
                                " %u  %.1f dBFS\n",
                        (unsigned long long)d->fno, s, sdb);
            }
        }
    }

    if (is_dl) {
        g_cells_dl.store(have);
        if (have < PKTS_PER_FRAME) g_partial_dl++;
    } else {
        g_cells_ul.store(have);
        if (have < PKTS_PER_FRAME) g_partial_ul++;
    }

    d->fno++;
    memset(d->seen, 0, sizeof d->seen);
}

/* hot path: each sample touched once, straight out of the capture buffer */
static void on_packet(unsigned char *user, const struct pcap_pkthdr *h,
                      const unsigned char *bytes)
{
    (void)user;

    if (h->caplen < ETH_HDR + ECPRI_HDR_SIZE) { g_bad++; return; }

    const unsigned char *b = bytes + ETH_HDR;
    if (((b[0] >> 4) & 0x0F) != 1 || b[1] != 0x00) { g_bad++; return; }

    uint16_t v;
    memcpy(&v, b + 6, 2);
    uint16_t seq = ntohs(v);
    if (seq < 1 || seq > PKTS_PER_FRAME) { g_bad++; return; }

    /* direction is the source MAC and nothing else - decided before the
       slot number is even computed */
    bool is_dl = (memcmp(bytes + 6, g_gnb, 6) == 0);
    dir_t *d   = is_dl ? &g_dl : &g_ul;

    uint32_t cell = (uint32_t)seq - 1;

    if (d->started && cell < d->last_cell) {
        if (d->last_cell - cell > WRAP_MIN) finish_frame(d);
        else                                g_reorder++;
    }
    d->started   = 1;
    d->last_cell = cell;
    d->seen[cell] = 1;
    if (is_dl) g_pkts_dl++; else g_pkts_ul++;

    /* arrival time against claimed position */
    if (cell == 0) {
        d->t0 = h->ts;
        d->t0_valid = 1;
        if (g_dl.t0_valid && g_ul.t0_valid) {
            double sk = us_between(&g_dl.t0, &g_ul.t0);
            while (sk >  5000.0) sk -= 10000.0;
            while (sk < -5000.0) sk += 10000.0;
            g_skew_us.store(sk);
        }
    } else if (d->t0_valid) {
        double err = us_between(&d->t0, &h->ts) - (double)cell * US_PER_PKT;
        if (fabs(err) > fabs(d->late_max)) {
            d->late_max = err;
            (is_dl ? g_late_dl : g_late_ul).store(err);
        }
    }

    if (h->caplen < ETH_HDR + ECPRI_HDR_SIZE + IQ_BYTES) { g_trunc++; return; }

    const int16_t *iq = (const int16_t *)(b + ECPRI_HDR_SIZE);
    uint64_t acc = 0, n = 0;
    for (int i = 0; i < SAMPLES_PER_PKT; i++) {
        int64_t I = iq[2 * i];
        int64_t Q = iq[2 * i + 1];
        acc += (uint64_t)(I * I) + (uint64_t)(Q * Q);
        n   += 2;
    }

    d->acc[cell]   += acc;
    d->nsamp[cell] += n;
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
        g_dl.late_max = 0.0;
        g_ul.late_max = 0.0;
    }
}

static void capture_thread(const char *iface, unsigned ethertype)
{
    char err[PCAP_ERRBUF_SIZE] = {0};

    g_ph = pcap_create(iface, err);
    if (!g_ph) { std::cerr << "pcap_create: " << err << "\n"; return; }

    /* buffer size must be set BEFORE activation */
    pcap_set_snaplen(g_ph, 65535);
    pcap_set_promisc(g_ph, 1);
    pcap_set_timeout(g_ph, 50);
    pcap_set_buffer_size(g_ph, 256 * 1024 * 1024);

    if (pcap_activate(g_ph) < 0) {
        std::cerr << "pcap_activate: " << pcap_geterr(g_ph) << "\n";
        std::cerr << "  setcap \"cap_net_raw,cap_net_admin=eip\" on the binary\n";
        return;
    }

    char filter[64];
    struct bpf_program fp;
    snprintf(filter, sizeof filter, "ether proto 0x%04x", ethertype);

    /* the filter runs inside the kernel: non-matching frames are discarded
       before they are ever copied to this process */
    if (pcap_compile(g_ph, &fp, filter, 1, PCAP_NETMASK_UNKNOWN) == 0) {
        pcap_setfilter(g_ph, &fp);
        pcap_freecode(&fp);
    }

    while (g_running.load()) {
        int n = pcap_dispatch(g_ph, -1, on_packet, NULL);
        if (n == -1 || n == -2) break;
    }
}

/* ---- drawing ---------------------------------------------------------- */

static double g_xs[PKTS_PER_FRAME];          /* x in slot units, 0..20 */
static double g_grid[SLOTS_PER_FRAME + 1];
static double g_y[PKTS_PER_FRAME], g_p[PKTS_PER_FRAME];

static double      g_tick_pos[SLOTS_PER_FRAME];
static char        g_tick_buf[SLOTS_PER_FRAME][4];
static const char *g_tick_lbl[SLOTS_PER_FRAME];

static void draw_trace(const char *title, const float *cur, const float *pk,
                       ImVec4 col, bool show_x)
{
    double top = SILENT_DB;
    for (int c = 0; c < PKTS_PER_FRAME; c++) {
        g_y[c] = cur[c];
        g_p[c] = pk[c];
        if (g_p[c] > top) top = g_p[c];
    }

    if (top <= QUIET_DB) top = -20.0;
    top = ceil(top / 5.0) * 5.0;
    double bot = g_autoscale ? top - 40.0 : SILENT_DB;
    if (!g_autoscale) top = 0.0;

    ImPlotAxisFlags xf = ImPlotAxisFlags_Lock;
    if (!show_x) xf |= ImPlotAxisFlags_NoTickLabels;

    if (ImPlot::BeginPlot(title, ImVec2(-1, -1), ImPlotFlags_NoLegend)) {
        ImPlot::SetupAxes(show_x ? "slot" : NULL, "dBFS",
                          xf, ImPlotAxisFlags_Lock);
        ImPlot::SetupAxisLimits(ImAxis_X1, 0, SLOTS_PER_FRAME, ImPlotCond_Always);
        ImPlot::SetupAxisLimits(ImAxis_Y1, bot, top, ImPlotCond_Always);
        ImPlot::SetupAxisTicks(ImAxis_X1, g_tick_pos, SLOTS_PER_FRAME, g_tick_lbl);

        /* slot boundaries */
        ImPlot::SetNextLineStyle(ImVec4(0.45f, 0.45f, 0.45f, 0.30f), 1.0f);
        ImPlot::PlotInfLines("##grid", g_grid, SLOTS_PER_FRAME + 1);

        if (g_show_peak) {
            ImPlot::SetNextLineStyle(ImVec4(col.x, col.y, col.z, 0.40f), 1.0f);
            ImPlot::PlotLine("##peak", g_xs, g_p, PKTS_PER_FRAME);
        }

        ImPlot::SetNextFillStyle(col, 0.25f);
        ImPlot::PlotShaded("##fill", g_xs, g_y, PKTS_PER_FRAME, bot);

        ImPlot::SetNextLineStyle(col, 1.8f);
        ImPlot::PlotLine("##trace", g_xs, g_y, PKTS_PER_FRAME);

        ImPlot::EndPlot();
    }
}

static void glfwErrorCallback(int e, const char *d)
{
    std::cerr << "GLFW error " << e << ": " << d << '\n';
}

int main(int argc, char **argv)
{
    if (argc < 3) {
        std::cerr << "usage: " << argv[0] << " <iface> <gnb-mac> [ethertype]\n"
                  << "  e.g. " << argv[0] << " sfp1 bc:24:11:ec:73:d3\n";
        return 1;
    }

    unsigned int m[6];
    if (sscanf(argv[2], "%x:%x:%x:%x:%x:%x",
               &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]) != 6) {
        std::cerr << "bad MAC: " << argv[2] << "\n";
        return 1;
    }
    for (int i = 0; i < 6; i++) g_gnb[i] = (unsigned char)m[i];

    unsigned ethertype = (argc > 3) ? (unsigned)strtoul(argv[3], NULL, 0)
                                    : 0xaefe;

    memset(&g_dl, 0, sizeof g_dl);
    memset(&g_ul, 0, sizeof g_ul);
    g_dl.tag = 'D';
    g_ul.tag = 'U';

    for (int c = 0; c < PKTS_PER_FRAME; c++) {
        g_cur_dl[c] = g_cur_ul[c] = (float)SILENT_DB;
        g_pk_dl[c]  = g_pk_ul[c]  = (float)SILENT_DB;
        g_xs[c] = (double)c / (double)PKTS_PER_SLOT;    /* slot units */
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
    io.FontGlobalScale = 1.2f;

    ImGui_ImplGlfw_InitForOpenGL(window, true);
    ImGui_ImplOpenGL3_Init("#version 130");

    std::thread cap(capture_thread, argv[1], ethertype);
    std::thread sta(stats_thread);

    const ImVec4 COL_DL(1.00f, 0.72f, 0.15f, 1.0f);
    const ImVec4 COL_UL(0.35f, 0.85f, 0.35f, 1.0f);
    const ImVec4 COL_OK(0.30f, 1.00f, 0.30f, 1.0f);
    const ImVec4 COL_BAD(1.00f, 0.25f, 0.25f, 1.0f);

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

        ImGui::Text("%s   DL src %s   |   DL %llu pkts  %u/640 cells  partial %llu"
                    "   |   UL %llu pkts  %u/640 cells  partial %llu",
                    argv[1], argv[2],
                    (unsigned long long)g_pkts_dl.load(), g_cells_dl.load(),
                    (unsigned long long)g_partial_dl.load(),
                    (unsigned long long)g_pkts_ul.load(), g_cells_ul.load(),
                    (unsigned long long)g_partial_ul.load());

        if (drop || ifdrop)
            ImGui::TextColored(COL_BAD,
                "drop=+%u ifdrop=+%u  bad=%llu trunc=%llu reorder=%llu"
                "   << LOSSY, the trace has holes",
                drop, ifdrop, (unsigned long long)g_bad.load(),
                (unsigned long long)g_trunc.load(),
                (unsigned long long)g_reorder.load());
        else
            ImGui::TextColored(COL_OK,
                "drop=0 ifdrop=0  bad=%llu trunc=%llu reorder=%llu   clean",
                (unsigned long long)g_bad.load(),
                (unsigned long long)g_trunc.load(),
                (unsigned long long)g_reorder.load());

        ImGui::Text("timing:  DL worst %+8.1f us   UL worst %+8.1f us"
                    "   UL-DL frame skew %+8.1f us   |   %.0f FPS",
                    g_late_dl.load(), g_late_ul.load(), g_skew_us.load(),
                    io.Framerate);

        if (g_viol_n.load())
            ImGui::TextColored(COL_BAD,
                "!! %llu TDD violations - uplink in a downlink slot."
                "  last: frame %llu  slot %d  %.1f dBFS",
                (unsigned long long)g_viol_n.load(),
                (unsigned long long)g_viol_frame.load(),
                g_viol_slot.load(), g_viol_db.load());

        ImGui::Checkbox("peak hold", &g_show_peak);
        ImGui::SameLine();
        if (ImGui::Button("clear")) g_clear_peak.store(true);
        ImGui::SameLine();
        ImGui::Checkbox("auto range each channel", &g_autoscale);
        ImGui::SameLine();
        ImGui::TextDisabled("(640 points per frame, 15.625 us each)");

        if (ImPlot::BeginSubplots("##stack", 2, 1, ImVec2(-1, -1),
                                  ImPlotSubplotFlags_LinkCols)) {
            draw_trace("DL   gNB -> UE", g_cur_dl, g_pk_dl, COL_DL, false);
            draw_trace("UL   UE -> gNB", g_cur_ul, g_pk_ul, COL_UL, true);
            ImPlot::EndSubplots();
        }

        ImGui::End();

        ImGui::Render();
        int w, h;
        glfwGetFramebufferSize(window, &w, &h);
        glViewport(0, 0, w, h);
        glClearColor(0.06f, 0.07f, 0.09f, 1.00f);
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
