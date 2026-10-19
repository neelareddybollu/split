/* -------------------------------------------------------------------------
 * live4.c - live Split 8 fronthaul display, with a per-frame log
 *
 * Same display as live3: peak dBFS per slot per direction, redrawn once a
 * second, with the slot number on both columns.
 *
 * New here: every completed frame writes one line to STDERR carrying all
 * twenty slot values for that frame. stdout stays the display, so the two
 * are separated by redirecting stderr:
 *
 *     gcc -O2 -o live4 live4.c -lpcap -lm
 *     sudo ./live4 sfp1 bc:24:11:ec:73:d3 2> frames.log
 *
 * Log format, one line per frame per direction:
 *
 *     D <frame> <slot0> <slot1> ... <slot19>
 *     U <frame> <slot0> <slot1> ... <slot19>
 *
 * so column 3 is slot 0, column 4 is slot 1, and in general slot s is
 * column 3+s. Silent slots read -120.0.
 *
 * The point of the log is periodicity. The display's one-second peak hold
 * cannot tell a 20 ms signal from a 1 s one - both light the slot in every
 * second. Per frame, they are obviously different:
 *
 *     gap of 2 frames    -> 20 ms   SSB or SIB1
 *     gap of 128 frames  -> 1.28 s  paging
 *     no repeating gap   ->         traffic or signalling
 *
 * To histogram the gaps for slot S of the downlink:
 *
 *     awk -v c=$((3+S)) '$1=="D" && $c > -100 {if (p) print $2-p; p=$2}' \
 *         frames.log | sort -n | uniq -c | sort -rn | head
 * ---------------------------------------------------------------------- */

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
#define IQ_BYTES         7680
#define FULL_SCALE       32767.0
#define SILENT_DB        (-120.0)
#define BARW               24

/* One direction.  No frame buffer: energy is accumulated per slot as the
   packets arrive, so the IQ is touched exactly once, while it is still in
   cache, and never copied anywhere. */
typedef struct {
    const char *name;
    char        tag;                    /* 'D' or 'U' in the log */
    uint64_t    acc[SLOTS_PER_FRAME];   /* running sum of I^2 + Q^2 */
    double      peak[SLOTS_PER_FRAME];  /* loudest dBFS this second */
    uint8_t     seen[PKTS_PER_FRAME];
    uint32_t    last_cell, cells_max;
    int         started;
    uint64_t    pkts, frames;
    uint64_t    fno;                    /* frames since start, for the log */
} dir_t;

static dir_t g_dl = { "DL (gNB -> UE)", 'D' };
static dir_t g_ul = { "UL (UE -> gNB)", 'U' };

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

/* A frame has ended: turn each slot's accumulator into dBFS, log this
   frame's twenty values, keep the loudest seen this second, then clear for
   the next frame.  No memset of a big buffer, no scan over a megabyte of
   samples. */
static void finish_frame(dir_t *d)
{
    double cur[SLOTS_PER_FRAME];

    uint32_t have = 0;
    for (uint32_t c = 0; c < PKTS_PER_FRAME; c++) have += d->seen[c];
    if (have > d->cells_max) d->cells_max = have;

    for (uint32_t s = 0; s < SLOTS_PER_FRAME; s++) {
        double db = SILENT_DB;
        if (d->acc[s] > 0) {
            double mean = (double)d->acc[s] / (double)SAMPLES_PER_SLOT;
            db = 10.0 * log10(mean / (FULL_SCALE * FULL_SCALE));
            if (db < SILENT_DB) db = SILENT_DB;
        }
        cur[s] = db;
        if (db > d->peak[s]) d->peak[s] = db;
        d->acc[s] = 0;
    }

    /* per-frame log on stderr: tag, frame number, twenty slot values */
    fprintf(stderr, "%c %llu", d->tag, (unsigned long long)d->fno);
    for (uint32_t s = 0; s < SLOTS_PER_FRAME; s++)
        fprintf(stderr, " %.1f", cur[s]);
    fputc('\n', stderr);
    d->fno++;

    memset(d->seen, 0, sizeof d->seen);
    d->frames++;
}

/* the display window is reset every second; fno is NOT, so frame numbers in
   the log run continuously from the start of the capture */
static void reset_window(dir_t *d)
{
    for (uint32_t s = 0; s < SLOTS_PER_FRAME; s++) d->peak[s] = SILENT_DB;
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

    printf("  slot   %-*s          slot   %-*s\n",
           BARW, g_dl.name, BARW, g_ul.name);

    for (uint32_t s = 0; s < SLOTS_PER_FRAME; s++) {
        char bd[BARW + 1], bu[BARW + 1];
        bar(bd, g_dl.peak[s]);
        bar(bu, g_ul.peak[s]);
        printf("   %2u   |%s| %6.1f    %2u   |%s| %6.1f\n",
               s, bd, g_dl.peak[s], s, bu, g_ul.peak[s]);
    }

    printf("\n  peak over the last second.  Ctrl-C to stop.\n");
    fflush(stdout);

    reset_window(&g_dl);
    reset_window(&g_ul);
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

    uint32_t cell = (uint32_t)seq - 1;
    if (d->started && cell < d->last_cell) finish_frame(d);
    d->started   = 1;
    d->last_cell = cell;
    d->pkts++;

    if (h->caplen < ETH_HDR + ECPRI_HDR_SIZE + IQ_BYTES) { g_trunc++; return; }

    /* Square and accumulate straight out of the capture buffer. */
    const int16_t *iq = (const int16_t *)(b + ECPRI_HDR_SIZE);
    uint64_t acc = 0;
    for (int i = 0; i < SAMPLES_PER_PKT * 2; i++) {
        int32_t s16 = iq[i];
        acc += (uint64_t)(s16 * s16);
    }

    d->acc[cell / PKTS_PER_SLOT] += acc;
    d->seen[cell] = 1;
}

int main(int argc, char **argv)
{
    char err[PCAP_ERRBUF_SIZE];

    if (argc < 3) {
        fprintf(stderr, "usage: sudo %s <iface> <gnb-mac> [ethertype]\n", argv[0]);
        fprintf(stderr, "  e.g. sudo %s sfp1 bc:24:11:ec:73:d3 0xaefe\n", argv[0]);
        fprintf(stderr, "  per-frame log goes to stderr: ... 2> frames.log\n");
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
