#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <math.h>
#include <arpa/inet.h>
#include <pcap.h>

#define ETH_HDR            14
#define ECPRI_HDR_SIZE      8
#define SAMPLES_PER_PKT  1920
#define PKTS_PER_SLOT      32
#define PKTS_PER_FRAME    640
#define SLOTS_PER_FRAME    20
#define SAMPLES_PER_SLOT 61440
#define SAMPLES_PER_FRAME 1228800
#define IQ_BYTES         7680
#define FULL_SCALE       32767.0
#define BARW               22

static int16_t  g_frame[SAMPLES_PER_FRAME * 2];
static uint8_t  g_seen[PKTS_PER_FRAME];
static double   g_peak[SLOTS_PER_FRAME];
static uint32_t g_last_cell, g_cells_max;
static int      g_started;
static uint64_t g_ok, g_bad, g_trunc, g_frames;

static double slot_db(uint32_t s)
{
    const int16_t *p = &g_frame[(size_t)s * SAMPLES_PER_SLOT * 2];
    double acc = 0.0;

    for (uint32_t i = 0; i < SAMPLES_PER_SLOT; i++) {
        double re = p[2 * i];
        double im = p[2 * i + 1];
        acc += re * re + im * im;
    }

    double mean = acc / (double)SAMPLES_PER_SLOT;
    return (mean > 0.0)
         ? 10.0 * log10(mean / (FULL_SCALE * FULL_SCALE))
         : -120.0;
}

static void finish_frame(void)
{
    uint32_t have = 0;
    for (uint32_t c = 0; c < PKTS_PER_FRAME; c++) have += g_seen[c];
    if (have > g_cells_max) g_cells_max = have;

    for (uint32_t s = 0; s < SLOTS_PER_FRAME; s++) {
        double db = slot_db(s);
        if (db > g_peak[s]) g_peak[s] = db;
    }

    memset(g_frame, 0, sizeof g_frame);
    memset(g_seen,  0, sizeof g_seen);
    g_frames++;
}

static void on_packet(unsigned char *user,
                      const struct pcap_pkthdr *h,
                      const unsigned char *bytes)
{
    (void)user;
    if (h->caplen < ETH_HDR + ECPRI_HDR_SIZE) { g_bad++; return; }

    const uint8_t *b = bytes + ETH_HDR;
    if (((b[0] >> 4) & 0x0F) != 1 || b[1] != 0x00) { g_bad++; return; }

    uint16_t v, seq;
    memcpy(&v, b + 6, 2);  seq = ntohs(v);
    if (seq < 1 || seq > PKTS_PER_FRAME) { g_bad++; return; }

    uint32_t cell = (uint32_t)seq - 1;

    if (g_started && cell < g_last_cell) finish_frame();
    g_started   = 1;
    g_last_cell = cell;

    if (h->caplen < ETH_HDR + ECPRI_HDR_SIZE + IQ_BYTES) { g_trunc++; return; }

    memcpy(&g_frame[(size_t)cell * SAMPLES_PER_PKT * 2],
           b + ECPRI_HDR_SIZE, IQ_BYTES);
    g_seen[cell] = 1;
    g_ok++;
}

static void analyse(const char *path, double *out)
{
    char err[PCAP_ERRBUF_SIZE];

    memset(g_frame, 0, sizeof g_frame);
    memset(g_seen,  0, sizeof g_seen);
    for (uint32_t s = 0; s < SLOTS_PER_FRAME; s++) g_peak[s] = -120.0;
    g_ok = g_bad = g_trunc = g_frames = 0;
    g_started = 0;
    g_cells_max = 0;

    for (uint32_t s = 0; s < SLOTS_PER_FRAME; s++) out[s] = -120.0;

    pcap_t *ph = pcap_open_offline(path, err);
    if (!ph) { fprintf(stderr, "%s: %s\n", path, err); return; }
    pcap_loop(ph, 0, on_packet, NULL);
    pcap_close(ph);

    if (g_started) finish_frame();

    printf("%-14s ok=%lu bad=%lu trunc=%lu  frames=%lu  best cells=%u/%d\n",
           path, (unsigned long)g_ok, (unsigned long)g_bad,
           (unsigned long)g_trunc, (unsigned long)g_frames,
           g_cells_max, PKTS_PER_FRAME);

    for (uint32_t s = 0; s < SLOTS_PER_FRAME; s++) out[s] = g_peak[s];
}

static void bar(char *o, double db)
{
    int n = (int)((db + 90.0) / 90.0 * BARW);
    if (n < 0) n = 0;
    if (n > BARW) n = BARW;
    memset(o, ' ', BARW);
    memset(o, '#', (size_t)n);
    o[BARW] = '\0';
}

int main(int argc, char **argv)
{
    static double a[SLOTS_PER_FRAME], b[SLOTS_PER_FRAME];

    if (argc < 2) {
        fprintf(stderr, "usage: %s <file-a.pcap> [file-b.pcap]\n", argv[0]);
        return 1;
    }

    analyse(argv[1], a);
    if (argc > 2) analyse(argv[2], b);
    printf("\n");

    if (argc > 2) printf("        %-*s          %-*s\n", BARW, argv[1], BARW, argv[2]);
    else          printf("        %s\n", argv[1]);

    for (uint32_t s = 0; s < SLOTS_PER_FRAME; s++) {
        char ba[BARW + 1], bb[BARW + 1];
        bar(ba, a[s]);
        printf(" %2u |%s| %6.1f", s, ba, a[s]);
        if (argc > 2) { bar(bb, b[s]); printf("  |%s| %6.1f", bb, b[s]); }
        printf("\n");
    }
    return 0;
}
