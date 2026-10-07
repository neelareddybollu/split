#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <pthread.h>
#include <atomic>
#include <arpa/inet.h>
#include <pcap.h>

#include "imgui.h"
#include "imgui_impl_glfw.h"
#include "imgui_impl_opengl3.h"
#include "implot.h"
#include <GLFW/glfw3.h>

#define ETH_HDR            14
#define ECPRI_HDR_SIZE      8
#define SAMPLES_PER_PKT  1920
#define PKTS_PER_SLOT      32
#define PKTS_PER_FRAME    640
#define SLOTS              20
#define SAMPLES_PER_SLOT 61440
#define IQ_BYTES         7680
#define FULL_SCALE       32767.0
#define HIST              400          /* 4 seconds of history */

/* ---------- shared between the two threads ---------- */

static float  g_wf_dl[HIST][SLOTS];
static float  g_wf_ul[HIST][SLOTS];
static std::atomic<int>      g_row(0);
static std::atomic<uint64_t> g_pkts_dl(0), g_pkts_ul(0), g_frames(0);
static std::atomic<uint32_t> g_drop(0), g_ifdrop(0);
static std::atomic<bool>     g_running(true);

/* ---------- capture side ---------- */

typedef struct {
    uint64_t acc[SLOTS];
    uint8_t  seen[PKTS_PER_FRAME];
    uint32_t last_cell;
    int      started;
} dir_t;

static dir_t    g_dl, g_ul;
static pcap_t  *g_ph;
static uint8_t  g_gnb[6];

static int parse_mac(const char *s, uint8_t m[6])
{
    return sscanf(s, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                  &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]) == 6 ? 0 : -1;
}

static void finish(dir_t *d, float *out)
{
    for (int s = 0; s < SLOTS; s++) {
        float db = -120.0f;
        if (d->acc[s] > 0) {
            double mean = (double)d->acc[s] / (double)SAMPLES_PER_SLOT;
            db = (float)(10.0 * log10(mean / (FULL_SCALE * FULL_SCALE)));
        }
        out[s] = db;
        d->acc[s] = 0;
    }
    memset(d->seen, 0, sizeof d->seen);
}

static void on_packet(unsigned char *,
                      const struct pcap_pkthdr *h,
                      const unsigned char *bytes)
{
    if (h->caplen < ETH_HDR + ECPRI_HDR_SIZE) return;

    const uint8_t *b = bytes + ETH_HDR;
    if (((b[0] >> 4) & 0x0F) != 1 || b[1] != 0x00) return;

    uint16_t v, seq;
    memcpy(&v, b + 6, 2);  seq = ntohs(v);
    if (seq < 1 || seq > PKTS_PER_FRAME) return;

    bool   is_dl = (memcmp(bytes + 6, g_gnb, 6) == 0);
    dir_t *d     = is_dl ? &g_dl : &g_ul;
    uint32_t cell = (uint32_t)seq - 1;

    if (d->started && cell < d->last_cell) {
        int r = g_row.load();
        finish(d, is_dl ? g_wf_dl[r] : g_wf_ul[r]);
        if (is_dl) {                       /* DL drives the row advance */
            g_row.store((r + 1) % HIST);
            g_frames++;
            struct pcap_stat st;
            if (pcap_stats(g_ph, &st) == 0) {
                g_drop.store(st.ps_drop);
                g_ifdrop.store(st.ps_ifdrop);
            }
        }
    }
    d->started   = 1;
    d->last_cell = cell;

    if (is_dl) g_pkts_dl++; else g_pkts_ul++;

    if (h->caplen < ETH_HDR + ECPRI_HDR_SIZE + IQ_BYTES) return;

    const int16_t *iq = (const int16_t *)(b + ECPRI_HDR_SIZE);
    uint64_t acc = 0;
    for (int i = 0; i < SAMPLES_PER_PKT * 2; i++) {
        int32_t s = iq[i];
        acc += (uint64_t)(s * s);
    }
    d->acc[cell / PKTS_PER_SLOT] += acc;
    d->seen[cell] = 1;
}

static void *capture_thread(void *)
{
    pcap_loop(g_ph, 0, on_packet, NULL);
    g_running.store(false);
    return NULL;
}

/* ---------- display side ---------- */

static void draw_waterfall(const char *title, float wf[HIST][SLOTS])
{
    static float snap[HIST * SLOTS];
    int head = g_row.load();

    for (int r = 0; r < HIST; r++) {
        int src = (head + r) % HIST;              /* oldest first */
        memcpy(&snap[r * SLOTS], wf[src], SLOTS * sizeof(float));
    }

    if (ImPlot::BeginPlot(title, ImVec2(-1, 320))) {
        ImPlot::SetupAxes("slot", "time",
                          ImPlotAxisFlags_Lock, ImPlotAxisFlags_Lock);
        ImPlot::SetupAxisLimits(ImAxis_X1, 0, SLOTS);
        ImPlot::SetupAxisLimits(ImAxis_Y1, 0, HIST);
        ImPlot::PlotHeatmap("##hm", snap, HIST, SLOTS, -90.0, 0.0, NULL,
                            ImPlotPoint(0, 0), ImPlotPoint(SLOTS, HIST));
        ImPlot::EndPlot();
    }
}

int main(int argc, char **argv)
{
    char err[PCAP_ERRBUF_SIZE];

    if (argc < 3) {
        fprintf(stderr, "usage: sudo %s <iface> <gnb-mac> [ethertype]\n", argv[0]);
        return 1;
    }
    if (parse_mac(argv[2], g_gnb) != 0) {
        fprintf(stderr, "bad MAC: %s\n", argv[2]);
        return 1;
    }
    unsigned ethertype = (argc > 3) ? (unsigned)strtoul(argv[3], NULL, 0) : 0xaefe;

    for (int r = 0; r < HIST; r++)
        for (int s = 0; s < SLOTS; s++)
            g_wf_dl[r][s] = g_wf_ul[r][s] = -120.0f;

    /* --- capture --- */
    g_ph = pcap_create(argv[1], err);
    if (!g_ph) { fprintf(stderr, "pcap_create: %s\n", err); return 1; }
    pcap_set_snaplen(g_ph, 65535);
    pcap_set_promisc(g_ph, 1);
    pcap_set_timeout(g_ph, 100);
    pcap_set_buffer_size(g_ph, 256 * 1024 * 1024);
    if (pcap_activate(g_ph) < 0) {
        fprintf(stderr, "pcap_activate: %s (need sudo?)\n", pcap_geterr(g_ph));
        return 1;
    }

    char filter[64];
    struct bpf_program fp;
    snprintf(filter, sizeof filter, "ether proto 0x%04x", ethertype);
    if (pcap_compile(g_ph, &fp, filter, 1, PCAP_NETMASK_UNKNOWN) < 0 ||
        pcap_setfilter(g_ph, &fp) < 0) {
        fprintf(stderr, "filter: %s\n", pcap_geterr(g_ph));
        return 1;
    }
    pcap_freecode(&fp);

    pthread_t th;
    pthread_create(&th, NULL, capture_thread, NULL);

    /* --- window --- */
    if (!glfwInit()) { fprintf(stderr, "glfwInit failed\n"); return 1; }
    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
    glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 0);

    GLFWwindow *win = glfwCreateWindow(1100, 820,
                                       "Split 8 fronthaul scope", NULL, NULL);
    if (!win) { fprintf(stderr, "no window - is DISPLAY set?\n"); return 1; }
    glfwMakeContextCurrent(win);
    glfwSwapInterval(1);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImPlot::CreateContext();
    ImGui::StyleColorsDark();
    ImGui_ImplGlfw_InitForOpenGL(win, true);
    ImGui_ImplOpenGL3_Init("#version 130");

    uint64_t last_dl = 0, last_ul = 0, last_fr = 0;
    uint32_t last_drop = 0;
    double   last_t = glfwGetTime();
    double   rate_dl = 0, rate_ul = 0, rate_fr = 0, rate_drop = 0;

    while (!glfwWindowShouldClose(win) && g_running.load()) {
        glfwPollEvents();

        double now = glfwGetTime();
        if (now - last_t >= 1.0) {
            uint64_t dl = g_pkts_dl.load(), ul = g_pkts_ul.load(),
                     fr = g_frames.load();
            uint32_t dr = g_drop.load();
            rate_dl   = (double)(dl - last_dl)   / (now - last_t);
            rate_ul   = (double)(ul - last_ul)   / (now - last_t);
            rate_fr   = (double)(fr - last_fr)   / (now - last_t);
            rate_drop = (double)(dr - last_drop) / (now - last_t);
            last_dl = dl; last_ul = ul; last_fr = fr; last_drop = dr;
            last_t = now;
        }

        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplGlfw_NewFrame();
        ImGui::NewFrame();

        ImGui::SetNextWindowPos(ImVec2(0, 0));
        ImGui::SetNextWindowSize(ImGui::GetIO().DisplaySize);
        ImGui::Begin("scope", NULL,
                     ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize |
                     ImGuiWindowFlags_NoMove);

        ImGui::Text("DL %.0f pkt/s    UL %.0f pkt/s    %.0f frames/s",
                    rate_dl, rate_ul, rate_fr);
        ImGui::SameLine();
        if (rate_drop > 0)
            ImGui::TextColored(ImVec4(1, 0.4f, 0.3f, 1),
                               "    drop %.0f/s", rate_drop);
        else
            ImGui::TextColored(ImVec4(0.4f, 1, 0.4f, 1), "    clean");

        ImPlot::PushColormap(ImPlotColormap_Viridis);
        draw_waterfall("downlink  (gNB -> UE)", g_wf_dl);
        draw_waterfall("uplink  (UE -> gNB)",   g_wf_ul);
        ImPlot::PopColormap();

        ImGui::Text("colour: -90 dBFS (dark) .. 0 dBFS (bright)   "
                    "x = slot 0..19   y = time, newest at top");

        ImGui::End();
        ImGui::Render();

        int w, h;
        glfwGetFramebufferSize(win, &w, &h);
        glViewport(0, 0, w, h);
        glClearColor(0.06f, 0.06f, 0.08f, 1.0f);
        glClear(GL_COLOR_BUFFER_BIT);
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
        glfwSwapBuffers(win);
    }

    pcap_breakloop(g_ph);
    pthread_join(th, NULL);
    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplGlfw_Shutdown();
    ImPlot::DestroyContext();
    ImGui::DestroyContext();
    glfwDestroyWindow(win);
    glfwTerminate();
    pcap_close(g_ph);
    return 0;
}
