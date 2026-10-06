#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <time.h>
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
#define BARW               24

typedef struct {
    const char *name;
    int16_t    *frame;
    uint8_t     seen[PKTS_PER_FRAME];
    double      peak[SLOTS_PER_FRAME];
    uint32_t    last_cell, cells_max;
    int         started;
    uint64_t    pkts, frames;
} dir_t;

static int16_t g_dl_buf[SAMPLES_PER_FRAME * 2];
static int16_t g_ul_buf[SAMPLES_PER_FRAME * 2];

static dir_t g_dl = { "DL (gNB -> UE)", g_dl_buf };
static dir_t g_ul = { "UL (UE -> gNB)", g_ul_buf };

static pcap_t  *g_ph;
static uint8_t  g_gnb[6];
static uint64_t g_bad, g_trunc;
static uint32_t g_prev_drop, g_prev_ifdrop;
static time_t   g_last_print;

static void on_sigint(int s) { (void)s; if (g_ph) pcap_breakloop(g_ph); }

static int parse_mac(const char *s, uint8_t m[6])
{
    return sscanf(s, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                  &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]) == 6 ? 0 : -1;
}

static double slot_db(const int16_t *frame, uint32_t s)
{
    const int16_t *p = &frame[(size_t)s * SAMPLES_PER_SLOT * 2];
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

static void finish_frame(dir_t *d)
{
    uint32_t have = 0;
    for (uint32_t c = 0; c < PKTS_PER_FRAME; c++) have += d->seen[c];
    if (have > d->cells_max) d->cells_max = have;

    for (uint32_t s = 0; s < SLOTS_PER_FRAME; s++) {
        double db = slot_db(d->frame, s);
        if (db > d->peak[s]) d->peak[s] = db;
    }

    memset(d->frame, 0, (size_t)SAMPLES_PER_FRAME * 2 * sizeof(int16_t));
    memset(d->seen, 0, sizeof d->seen);
    d->frames++;
}

static void reset_window(dir_t *d)
{
    for (uint32_t s = 0; s < SLOTS_PER_FRAME; s++) d->peak[s] = -120.0;
    d->cells_max = 0;
    d->frames = 0;
    d->pkts = 0;
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

static void draw(void)
{
    struct pcap_stat st;
    uint32_t d_drop = 0, d_ifdrop = 0;

    if (pcap_stats(g_ph, &st) == 0) {
        d_drop   = st.ps_drop   - g_prev_drop;
        d_ifdrop = st.ps_ifdrop - g_prev_ifdrop;
        g_prev_drop   = st.ps_drop;
        g_prev_ifdrop = st.ps_ifdrop;
    }

    printf("\033[H\033[J");

    printf("  Split 8 fronthaul   |   DL %lu pkts %lu frames %u/%d cells"
           "   |   UL %lu pkts %lu frames %u/%d cells\n",
           (unsigned long)g_dl.pkts, (unsigned long)g_dl.frames,
           g_dl.cells_max, PKTS_PER_FRAME,
           (unsigned long)g_ul.pkts, (unsigned long)g_ul.frames,
           g_ul.cells_max, PKTS_PER_FRAME);

    printf("  capture: drop=+%u ifdrop=+%u  bad=%lu trunc=%lu   %s\n\n",
           d_drop, d_ifdrop, (unsigned long)g_bad, (unsigned long)g_trunc,
           (d_drop || d_ifdrop) ? "<< LOSSY" : "clean");

    printf("  slot   %-*s        %-*s\n", BARW, g_dl.name, BARW, g_ul.name);

    for (uint32_t s = 0; s < SLOTS_PER_FRAME; s++) {
        char bd[BARW + 1], bu[BARW + 1];
        bar(bd, g_dl.peak[s]);
        bar(bu, g_ul.peak[s]);
        printf("   %2u   |%s| %6.1f   |%s| %6.1f\n",
               s, bd, g_dl.peak[s], bu, g_ul.peak[s]);
    }

    printf("\n  peak over the last second.  Ctrl-C to stop.\n");
    fflush(stdout);

    reset_window(&g_dl);
    reset_window(&g_ul);
}

static void place(dir_t *d, uint32_t cell, const uint8_t *iq, uint32_t caplen)
{
    if (d->started && cell < d->last_cell) finish_frame(d);
    d->started   = 1;
    d->last_cell = cell;
    d->pkts++;

    if (caplen < ETH_HDR + ECPRI_HDR_SIZE + IQ_BYTES) { g_trunc++; return; }

    memcpy(&d->frame[(size_t)cell * SAMPLES_PER_PKT * 2], iq, IQ_BYTES);
    d->seen[cell] = 1;
}

static void on_packet(unsigned char *user,
                      const struct pcap_pkthdr *h,
                      const unsigned char *bytes)
{
    (void)user;

    if (h->ts.tv_sec != g_last_print) {
        if (g_last_print) draw();
        g_last_print = h->ts.tv_sec;
    }

    if (h->caplen < ETH_HDR + ECPRI_HDR_SIZE) { g_bad++; return; }

    const uint8_t *b = bytes + ETH_HDR;
    if (((b[0] >> 4) & 0x0F) != 1 || b[1] != 0x00) { g_bad++; return; }

    uint16_t v, seq;
    memcpy(&v, b + 6, 2);  seq = ntohs(v);
    if (seq < 1 || seq > PKTS_PER_FRAME) { g_bad++; return; }

    dir_t *d = (memcmp(bytes + 6, g_gnb, 6) == 0) ? &g_dl : &g_ul;
    place(d, (uint32_t)seq - 1, b + ECPRI_HDR_SIZE, h->caplen);
}

int main(int argc, char **argv)
{
    char err[PCAP_ERRBUF_SIZE];

    if (argc < 3) {
        fprintf(stderr, "usage: sudo %s <iface> <gnb-mac> [ethertype]\n", argv[0]);
        fprintf(stderr, "  e.g. sudo %s sfp1 bc:24:11:ec:73:d3 0xaefe\n", argv[0]);
        return 1;
    }

    if (parse_mac(argv[2], g_gnb) != 0) {
        fprintf(stderr, "bad MAC: %s\n", argv[2]);
        return 1;
    }

    unsigned ethertype = (argc > 3) ? (unsigned)strtoul(argv[3], NULL, 0) : 0xaefe;

    reset_window(&g_dl);
    reset_window(&g_ul);

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

    signal(SIGINT, on_sigint);

    pcap_loop(g_ph, 0, on_packet, NULL);

    printf("\nstopped.\n");
    pcap_close(g_ph);
    return 0;
}
