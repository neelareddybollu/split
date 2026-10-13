/* -------------------------------------------------------------------------
 * live5.c - live Split 8 fronthaul display
 *
 * Reads eCPRI frames from a switch mirror port, separates the two
 * directions by source MAC, and shows the power in each of the twenty
 * slots of a 10 ms radio frame, redrawn once a second.
 *
 *   gcc -O3 -march=native -o live5 live5.c -lpcap -lm
 *   sudo ./live5 sfp1 bc:24:11:ec:73:d3
 *
 * Options
 *   -e <ethertype>  default 0xaefe
 *   -d <n>          decimate: use every n-th IQ sample pair (default 1)
 *   -t              timing mode: 64 byte snaplen, no energy, never drops
 *   -l              per-frame log to stderr
 *
 * Changes from live3 / live4
 *
 *   1. The display is driven by the wall clock, not by packet arrival.
 *      live3 redrew from inside on_packet, so a silent link froze the
 *      screen and looked exactly like a hung program. pcap_dispatch now
 *      returns on its timeout and the main loop redraws regardless.
 *
 *   2. A frame boundary needs a LARGE backward step in the cell number.
 *      Any backward step used to end the frame, so a two-packet
 *      reordering split one frame into two. A real wrap goes from ~639
 *      to ~0; a reordering moves by one or two.
 *
 *   3. Energy is divided by the samples actually received, not by the
 *      theoretical 61440. A slot missing packets used to read LOW, so
 *      the tool quietly under-reported power instead of flagging it.
 *      This also makes decimation exact rather than approximate.
 *
 *   4. Frames with holes are counted and shown. cells_max alone was the
 *      most flattering number available; the worst frame is the honest
 *      one.
 *
 *   5. The square is done in 64-bit. Safe at 16 bits either way, but one
 *      sample width away from silent overflow.
 *
 *   6. Decimation and a headers-only timing mode, both off by default.
 *
 * Log format with -l, one line per frame per direction:
 *
 *     D <frame> <slot0> ... <slot19>
 *     U <frame> <slot0> ... <slot19>
 *
 * so slot s is column 3+s. To histogram the gaps for downlink slot S:
 *
 *   awk -v c=$((3+S)) '$1=="D" && $c > -100 {if(p) print $2-p; p=$2}' \
 *       frames.log | sort -n | uniq -c | sort -rn | head
 * ---------------------------------------------------------------------- */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
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
#define IQ_BYTES         7680
#define FULL_SCALE       32767.0
#define SILENT_DB        (-120.0)
#define BARW               24

/* a real frame wrap goes 639 -> 0; anything smaller is a reordering */
#define WRAP_MIN         (PKTS_PER_FRAME / 2)

typedef struct {
    const char *name;
    char        tag;                     /* 'D' or 'U' in the log */
    uint64_t    acc[SLOTS_PER_FRAME];    /* sum of I^2 + Q^2 */
    uint64_t    nsamp[SLOTS_PER_FRAME];  /* samples actually summed */
    double      peak[SLOTS_PER_FRAME];   /* loudest dBFS this second */
    uint8_t     seen[PKTS_PER_FRAME];
    uint32_t    last_cell;
    uint32_t    cells_min, cells_max;
    int         started;
    uint64_t    pkts, frames, partial;
    uint64_t    fno;                     /* frames since start, for the log */
} dir_t;

static dir_t g_dl = { "DL (gNB -> UE)", 'D' };
static dir_t g_ul = { "UL (UE -> gNB)", 'U' };

static pcap_t  *g_ph;
static uint8_t  g_gnb[6];
static uint64_t g_bad, g_trunc, g_reorder;
static uint32_t g_prev_drop, g_prev_ifdrop;
static time_t   g_last_print;
static volatile sig_atomic_t g_run = 1;

static int g_decim  = 1;    /* use every n-th IQ sample pair */
static int g_timing = 0;    /* headers only, no energy */
static int g_log    = 0;    /* per-frame log on stderr */

static void on_sigint(int s)
{
    (void)s;
    g_run = 0;
    if (g_ph) pcap_breakloop(g_ph);
}

static int parse_mac(const char *s, uint8_t m[6])
{
    return sscanf(s, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                  &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]) == 6 ? 0 : -1;
}

/* A frame has ended.  Each slot's energy is divided by the samples that
   actually arrived, so a slot with holes reports its true level instead of
   a low one, and decimation needs no correction factor. */
static void finish_frame(dir_t *d)
{
    double cur[SLOTS_PER_FRAME];

    uint32_t have = 0;
    for (uint32_t c = 0; c < PKTS_PER_FRAME; c++) have += d->seen[c];

    if (have > d->cells_max) d->cells_max = have;
    if (have < d->cells_min) d->cells_min = have;
    if (have < PKTS_PER_FRAME) d->partial++;

    for (uint32_t s = 0; s < SLOTS_PER_FRAME; s++) {
        double db = SILENT_DB;
        if (d->nsamp[s] > 0 && d->acc[s] > 0) {
            double mean = (double)d->acc[s] / (double)d->nsamp[s];
            db = 10.0 * log10(mean / (FULL_SCALE * FULL_SCALE));
            if (db < SILENT_DB) db = SILENT_DB;
        }
        cur[s] = db;
        if (db > d->peak[s]) d->peak[s] = db;
        d->acc[s]   = 0;
        d->nsamp[s] = 0;
    }

    if (g_log) {
        fprintf(stderr, "%c %llu", d->tag, (unsigned long long)d->fno);
        for (uint32_t s = 0; s < SLOTS_PER_FRAME; s++)
            fprintf(stderr, " %.1f", cur[s]);
        fputc('\n', stderr);
    }
    d->fno++;

    memset(d->seen, 0, sizeof d->seen);
    d->frames++;
}

/* the one-second display window; fno is NOT reset, so log frame numbers
   run continuously from the start of the capture */
static void reset_window(dir_t *d)
{
    for (uint32_t s = 0; s < SLOTS_PER_FRAME; s++) d->peak[s] = SILENT_DB;
    d->cells_max = 0;
    d->cells_min = PKTS_PER_FRAME;
    d->frames    = 0;
    d->partial   = 0;
    d->pkts      = 0;
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

    if (g_ph && pcap_stats(g_ph, &st) == 0) {
        d_drop   = st.ps_drop   - g_prev_drop;
        d_ifdrop = st.ps_ifdrop - g_prev_ifdrop;
        g_prev_drop   = st.ps_drop;
        g_prev_ifdrop = st.ps_ifdrop;
    }

    printf("\033[H\033[J");

    printf("  Split 8 fronthaul%s%s\n",
           g_timing ? "   [timing mode: headers only, no energy]" : "",
           g_decim > 1 ? "   [decimated]" : "");

    printf("  DL %lu pkts %lu frames  cells %u..%u  partial %lu"
           "   |   UL %lu pkts %lu frames  cells %u..%u  partial %lu\n",
           (unsigned long)g_dl.pkts, (unsigned long)g_dl.frames,
           g_dl.cells_min > g_dl.cells_max ? 0 : g_dl.cells_min,
           g_dl.cells_max, (unsigned long)g_dl.partial,
           (unsigned long)g_ul.pkts, (unsigned long)g_ul.frames,
           g_ul.cells_min > g_ul.cells_max ? 0 : g_ul.cells_min,
           g_ul.cells_max, (unsigned long)g_ul.partial);

    printf("  capture: drop=+%u ifdrop=+%u  bad=%lu trunc=%lu reorder=%lu"
           "   %s\n\n",
           d_drop, d_ifdrop, (unsigned long)g_bad, (unsigned long)g_trunc,
           (unsigned long)g_reorder,
           (d_drop || d_ifdrop) ? "<< LOSSY" : "clean");

    if (g_dl.pkts == 0 && g_ul.pkts == 0)
        printf("  no packets this second - is the mirror up?\n\n");

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

    if (h->caplen < ETH_HDR + ECPRI_HDR_SIZE) { g_bad++; return; }

    const uint8_t *b = bytes + ETH_HDR;
    if (((b[0] >> 4) & 0x0F) != 1 || b[1] != 0x00) { g_bad++; return; }

    uint16_t v, seq;
    memcpy(&v, b + 6, 2);  seq = ntohs(v);
    if (seq < 1 || seq > PKTS_PER_FRAME) { g_bad++; return; }

    dir_t *d = (memcmp(bytes + 6, g_gnb, 6) == 0) ? &g_dl : &g_ul;
    uint32_t cell = (uint32_t)seq - 1;

    /* only a large backward step is a frame wrap; a small one is a
       reordering and must not split the frame in two */
    if (d->started && cell < d->last_cell) {
        if (d->last_cell - cell > WRAP_MIN) finish_frame(d);
        else                                g_reorder++;
    }
    d->started   = 1;
    d->last_cell = cell;
    d->pkts++;
    d->seen[cell] = 1;

    if (g_timing) return;

    if (h->caplen < ETH_HDR + ECPRI_HDR_SIZE + IQ_BYTES) { g_trunc++; return; }

    /* Square and accumulate straight out of the capture buffer: the packet
       was just written there, so it is still in cache.  Each sample is
       touched exactly once and never copied anywhere. */
    const int16_t *iq = (const int16_t *)(b + ECPRI_HDR_SIZE);
    uint64_t acc = 0;
    uint64_t n   = 0;
    for (int i = 0; i < SAMPLES_PER_PKT; i += g_decim) {
        int64_t I = iq[2 * i];
        int64_t Q = iq[2 * i + 1];
        acc += (uint64_t)(I * I) + (uint64_t)(Q * Q);
        n   += 2;
    }

    uint32_t slot = cell / PKTS_PER_SLOT;
    d->acc[slot]   += acc;
    d->nsamp[slot] += n;
}

static void usage(const char *p)
{
    fprintf(stderr,
        "usage: sudo %s [-e ethertype] [-d n] [-t] [-l] <iface> <gnb-mac>\n"
        "  -e <ethertype>  default 0xaefe\n"
        "  -d <n>          use every n-th IQ sample pair (default 1)\n"
        "  -t              timing mode: 64 byte snaplen, no energy\n"
        "  -l              per-frame log to stderr\n"
        "  e.g. sudo %s sfp1 bc:24:11:ec:73:d3\n"
        "       sudo %s -l sfp1 bc:24:11:ec:73:d3 2> frames.log\n",
        p, p, p);
}

int main(int argc, char **argv)
{
    char err[PCAP_ERRBUF_SIZE];
    unsigned ethertype = 0xaefe;
    int opt;

    while ((opt = getopt(argc, argv, "e:d:tlh")) != -1) {
        switch (opt) {
        case 'e': ethertype = (unsigned)strtoul(optarg, NULL, 0); break;
        case 'd': g_decim = atoi(optarg); if (g_decim < 1) g_decim = 1; break;
        case 't': g_timing = 1; break;
        case 'l': g_log = 1; break;
        default:  usage(argv[0]); return 1;
        }
    }

    if (argc - optind < 2) { usage(argv[0]); return 1; }

    const char *iface = argv[optind];
    if (parse_mac(argv[optind + 1], g_gnb) != 0) {
        fprintf(stderr, "bad MAC: %s\n", argv[optind + 1]);
        return 1;
    }

    reset_window(&g_dl);
    reset_window(&g_ul);

    g_ph = pcap_create(iface, err);
    if (!g_ph) { fprintf(stderr, "pcap_create: %s\n", err); return 1; }

    /* buffer size must be set BEFORE activation, which is why
       pcap_open_live cannot be used here */
    pcap_set_snaplen(g_ph, g_timing ? 64 : 65535);
    pcap_set_promisc(g_ph, 1);
    pcap_set_timeout(g_ph, 50);          /* so dispatch returns when idle */
    pcap_set_buffer_size(g_ph, 256 * 1024 * 1024);

    if (pcap_activate(g_ph) < 0) {
        fprintf(stderr, "pcap_activate: %s\n", pcap_geterr(g_ph));
        fprintf(stderr, "  need root, or: sudo setcap "
                        "\"cap_net_raw,cap_net_admin=eip\" %s\n", argv[0]);
        return 1;
    }

    if (pcap_datalink(g_ph) != DLT_EN10MB) {
        fprintf(stderr, "%s is not Ethernet\n", iface);
        return 1;
    }

    char filter[64];
    struct bpf_program fp;
    snprintf(filter, sizeof filter, "ether proto 0x%04x", ethertype);

    /* the filter runs inside the kernel: a frame that does not match is
       discarded before it is ever copied to this process */
    if (pcap_compile(g_ph, &fp, filter, 1, PCAP_NETMASK_UNKNOWN) < 0 ||
        pcap_setfilter(g_ph, &fp) < 0) {
        fprintf(stderr, "filter: %s\n", pcap_geterr(g_ph));
        return 1;
    }
    pcap_freecode(&fp);

    signal(SIGINT,  on_sigint);
    signal(SIGTERM, on_sigint);

    g_last_print = time(NULL);

    /* The display is driven by the clock, not by packet arrival.  A silent
       link now shows all -120 with the packet counters frozen, instead of
       leaving the last screen up and looking like a hang. */
    while (g_run) {
        int n = pcap_dispatch(g_ph, 256, on_packet, NULL);
        if (n == -1) {
            fprintf(stderr, "pcap_dispatch: %s\n", pcap_geterr(g_ph));
            break;
        }
        if (n == -2) break;                  /* pcap_breakloop */

        time_t now = time(NULL);
        if (now != g_last_print) {
            g_last_print = now;
            draw();
        }
    }

    draw();
    printf("\nstopped.\n");
    pcap_close(g_ph);
    return 0;
}
