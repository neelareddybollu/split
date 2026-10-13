/* -------------------------------------------------------------------------
 * live6.c - live Split 8 fronthaul display, with a resource grid
 *
 * Everything live5 does, plus: for one chosen slot it runs a 4096 point
 * FFT on each of the 14 OFDM symbols and prints which resource blocks
 * actually carry energy. That answers "what is in this slot" rather than
 * "how much is in this slot".
 *
 *   gcc -O3 -march=native -o live6 live6.c -lpcap -lm
 *   sudo ./live6 -s 0 sfp1 bc:24:11:ec:73:d3
 *
 * Options
 *   -s <slot>       slot to analyse, 0..19          (default 0)
 *   -u              analyse the uplink instead of the downlink
 *   -e <ethertype>  default 0xaefe
 *   -d <n>          decimate the energy path, every n-th sample pair
 *   -t              timing mode: 64 byte snaplen, no energy, no grid
 *   -l              per-frame log to stderr
 *
 * Why a grid identifies a channel and a power level does not
 *
 *   SSB     240 contiguous subcarriers = 20 PRB, over 4 symbols
 *   SIB1    a PDSCH allocation inside CORESET#0's bandwidth
 *   PDCCH   CORESET#0 width, first 1-3 symbols only
 *   PRACH   139 subcarriers at prach_msg1_FrequencyStart
 *   PUCCH   1-2 PRB at a band edge
 *
 *   None of those footprints overlap, so the grid settles identification
 *   instead of leaving it to inference from timing.
 *
 * Numerology, mu = 1, 273 PRB, 122.88 Msps
 *
 *   FFT size            4096           = 122.88e6 / 30e3
 *   symbols per slot    14
 *   cyclic prefix       352 on symbol 0, 288 on symbols 1..13
 *   check               352 + 13*288 + 14*4096 = 61440 = one slot
 *   subcarriers used    273 * 12 = 3276, centred on DC
 *   PRB k covers        sc = -1638 + 12k .. -1638 + 12k + 11
 *
 * Cost control
 *
 *   Only the 32 packets belonging to the chosen slot are copied, and only
 *   every ANALYSE_EVERY-th frame is transformed. At the default that is 14
 *   FFTs ten times a second, which does not disturb the capture path. The
 *   drop counter on screen is the check - if it leaves zero, raise
 *   ANALYSE_EVERY.
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

#define WRAP_MIN         (PKTS_PER_FRAME / 2)

/* ---- resource grid ---------------------------------------------------- */

#define NFFT             4096
#define NSYM               14
#define CP0               352
#define CP                288
#define NPRB              273
#define SC_PER_PRB         12
#define SC_FIRST        (-1638)          /* -NPRB*12/2 */
#define SLOT_SAMPLES    61440
#define GRID_COLS          91            /* 273 / 3 */
#define PRB_PER_COL         3
#define ANALYSE_EVERY      10            /* transform 1 frame in N */

static int   g_slot    = 0;              /* slot to analyse */
static int   g_grid_ul = 0;              /* analyse uplink instead */
static int   g_grid_on = 1;

static int16_t g_slotbuf[SLOT_SAMPLES * 2];
static uint8_t g_slotseen[PKTS_PER_SLOT];
static double  g_grid[NSYM][NPRB];       /* accumulated |X|^2 */
static uint32_t g_grid_n;                /* frames accumulated */
static uint64_t g_frame_tick;

static float g_wr[NFFT / 2], g_wi[NFFT / 2];
static float g_re[NFFT], g_im[NFFT];

static void fft_init(void)
{
    for (int k = 0; k < NFFT / 2; k++) {
        double a = -2.0 * M_PI * (double)k / (double)NFFT;
        g_wr[k] = (float)cos(a);
        g_wi[k] = (float)sin(a);
    }
}

/* iterative radix-2, in place, precomputed twiddles */
static void fft(float *re, float *im)
{
    for (int i = 1, j = 0; i < NFFT; i++) {
        int bit = NFFT >> 1;
        for (; j & bit; bit >>= 1) j ^= bit;
        j ^= bit;
        if (i < j) {
            float t;
            t = re[i]; re[i] = re[j]; re[j] = t;
            t = im[i]; im[i] = im[j]; im[j] = t;
        }
    }
    for (int len = 2; len <= NFFT; len <<= 1) {
        int half = len >> 1;
        int step = NFFT / len;
        for (int i = 0; i < NFFT; i += len) {
            for (int k = 0; k < half; k++) {
                float wr = g_wr[k * step], wi = g_wi[k * step];
                float xr = re[i + k + half], xi = im[i + k + half];
                float vr = xr * wr - xi * wi;
                float vi = xr * wi + xi * wr;
                float ur = re[i + k], ui = im[i + k];
                re[i + k]        = ur + vr;  im[i + k]        = ui + vi;
                re[i + k + half] = ur - vr;  im[i + k + half] = ui - vi;
            }
        }
    }
}

/* one slot of samples -> 14 x 273 power, accumulated */
static void analyse_slot(void)
{
    int off = 0;
    for (int sym = 0; sym < NSYM; sym++) {
        off += (sym == 0) ? CP0 : CP;

        for (int i = 0; i < NFFT; i++) {
            g_re[i] = (float)g_slotbuf[2 * (off + i)];
            g_im[i] = (float)g_slotbuf[2 * (off + i) + 1];
        }
        fft(g_re, g_im);

        for (int k = 0; k < NPRB; k++) {
            double p = 0.0;
            for (int j = 0; j < SC_PER_PRB; j++) {
                int sc  = SC_FIRST + k * SC_PER_PRB + j;
                int bin = (sc + NFFT) & (NFFT - 1);
                p += (double)g_re[bin] * g_re[bin]
                   + (double)g_im[bin] * g_im[bin];
            }
            g_grid[sym][k] += p;
        }
        off += NFFT;
    }
    g_grid_n++;
}

static char level_char(double db)
{
    if (db >=  -3.0) return '@';
    if (db >=  -6.0) return '%';
    if (db >= -10.0) return '#';
    if (db >= -15.0) return '*';
    if (db >= -20.0) return '+';
    if (db >= -25.0) return '=';
    if (db >= -30.0) return '-';
    if (db >= -40.0) return ':';
    if (db >= -50.0) return '.';
    return ' ';
}

static void draw_grid(void)
{
    if (!g_grid_on) return;

    printf("\n  resource grid   slot %d   %s   %u frames\n",
           g_slot, g_grid_ul ? "UL" : "DL", g_grid_n);

    if (g_grid_n == 0) {
        printf("  no complete copy of that slot yet\n");
        return;
    }

    double peak = 0.0;
    for (int s = 0; s < NSYM; s++)
        for (int k = 0; k < NPRB; k++)
            if (g_grid[s][k] > peak) peak = g_grid[s][k];

    if (peak <= 0.0) {
        printf("  slot is empty - every subcarrier reads zero\n");
        memset(g_grid, 0, sizeof g_grid);
        g_grid_n = 0;
        return;
    }

    printf("  sym  PRB 0%*s%d\n", GRID_COLS - 10, "", NPRB - 1);

    for (int s = 0; s < NSYM; s++) {
        char row[GRID_COLS + 1];
        for (int c = 0; c < GRID_COLS; c++) {
            double m = 0.0;
            for (int j = 0; j < PRB_PER_COL; j++) {
                int k = c * PRB_PER_COL + j;
                if (k < NPRB && g_grid[s][k] > m) m = g_grid[s][k];
            }
            row[c] = (m > 0.0) ? level_char(10.0 * log10(m / peak)) : ' ';
        }
        row[GRID_COLS] = '\0';
        printf("  %3d  |%s|\n", s, row);
    }

    /* occupied span per symbol, 20 dB below the peak */
    double thr = peak * 0.01;
    printf("\n  occupied PRB, 20 dB below peak:\n");
    for (int s = 0; s < NSYM; s++) {
        int lo = -1, hi = -1, n = 0;
        for (int k = 0; k < NPRB; k++)
            if (g_grid[s][k] >= thr) { if (lo < 0) lo = k; hi = k; n++; }
        if (lo < 0) continue;
        printf("    sym %2d   PRB %3d..%3d   %3d PRB\n", s, lo, hi, n);
    }

    printf("  key  @ %% # * + = - : .   strongest to 50 dB down\n");

    memset(g_grid, 0, sizeof g_grid);
    g_grid_n = 0;
}

/* ---- per-direction energy -------------------------------------------- */

typedef struct {
    const char *name;
    char        tag;
    uint64_t    acc[SLOTS_PER_FRAME];
    uint64_t    nsamp[SLOTS_PER_FRAME];
    double      peak[SLOTS_PER_FRAME];
    uint8_t     seen[PKTS_PER_FRAME];
    uint32_t    last_cell;
    uint32_t    cells_min, cells_max;
    int         started;
    uint64_t    pkts, frames, partial;
    uint64_t    fno;
} dir_t;

static dir_t g_dl = { "DL (gNB -> UE)", 'D' };
static dir_t g_ul = { "UL (UE -> gNB)", 'U' };

static pcap_t  *g_ph;
static uint8_t  g_gnb[6];
static uint64_t g_bad, g_trunc, g_reorder;
static uint32_t g_prev_drop, g_prev_ifdrop;
static time_t   g_last_print;
static volatile sig_atomic_t g_run = 1;

static int g_decim  = 1;
static int g_timing = 0;
static int g_log    = 0;

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

    /* the chosen slot is transformed only if every one of its 32 packets
       arrived; a hole would put garbage at a known subcarrier */
    int is_grid_dir = g_grid_ul ? (d == &g_ul) : (d == &g_dl);
    if (g_grid_on && is_grid_dir) {
        uint32_t got = 0;
        for (int i = 0; i < PKTS_PER_SLOT; i++) got += g_slotseen[i];
        if (got == PKTS_PER_SLOT && (g_frame_tick % ANALYSE_EVERY) == 0)
            analyse_slot();
        memset(g_slotseen, 0, sizeof g_slotseen);
        g_frame_tick++;
    }

    memset(d->seen, 0, sizeof d->seen);
    d->frames++;
}

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
           g_timing ? "   [timing mode]" : "",
           g_decim > 1 ? "   [decimated]" : "");

    printf("  DL %lu pkts  cells %u..%u  partial %lu"
           "   |   UL %lu pkts  cells %u..%u  partial %lu\n",
           (unsigned long)g_dl.pkts,
           g_dl.cells_min > g_dl.cells_max ? 0 : g_dl.cells_min,
           g_dl.cells_max, (unsigned long)g_dl.partial,
           (unsigned long)g_ul.pkts,
           g_ul.cells_min > g_ul.cells_max ? 0 : g_ul.cells_min,
           g_ul.cells_max, (unsigned long)g_ul.partial);

    printf("  capture: drop=+%u ifdrop=+%u  bad=%lu trunc=%lu reorder=%lu"
           "   %s\n",
           d_drop, d_ifdrop, (unsigned long)g_bad, (unsigned long)g_trunc,
           (unsigned long)g_reorder,
           (d_drop || d_ifdrop) ? "<< LOSSY" : "clean");

    if (g_dl.pkts == 0 && g_ul.pkts == 0)
        printf("  no packets this second - is the mirror up?\n");

    printf("\n  slot    DL dBFS    UL dBFS    (silent slots hidden)\n");
    for (uint32_t s = 0; s < SLOTS_PER_FRAME; s++) {
        if (g_dl.peak[s] <= SILENT_DB && g_ul.peak[s] <= SILENT_DB) continue;
        char bd[BARW + 1], bu[BARW + 1];
        bar(bd, g_dl.peak[s]);
        bar(bu, g_ul.peak[s]);
        printf("   %2u   |%s| %6.1f   |%s| %6.1f\n",
               s, bd, g_dl.peak[s], bu, g_ul.peak[s]);
    }

    draw_grid();

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

    int is_dl = (memcmp(bytes + 6, g_gnb, 6) == 0);
    dir_t *d  = is_dl ? &g_dl : &g_ul;
    uint32_t cell = (uint32_t)seq - 1;

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

    const int16_t *iq = (const int16_t *)(b + ECPRI_HDR_SIZE);
    uint32_t slot = cell / PKTS_PER_SLOT;

    /* copy only the chosen slot of the chosen direction: 32 packets in 640,
       so about 5% of the traffic is ever touched twice */
    if (g_grid_on && (int)slot == g_slot &&
        (g_grid_ul ? !is_dl : is_dl)) {
        uint32_t idx = cell % PKTS_PER_SLOT;
        memcpy(&g_slotbuf[idx * SAMPLES_PER_PKT * 2], iq, IQ_BYTES);
        g_slotseen[idx] = 1;
    }

    uint64_t acc = 0, n = 0;
    for (int i = 0; i < SAMPLES_PER_PKT; i += g_decim) {
        int64_t I = iq[2 * i];
        int64_t Q = iq[2 * i + 1];
        acc += (uint64_t)(I * I) + (uint64_t)(Q * Q);
        n   += 2;
    }

    d->acc[slot]   += acc;
    d->nsamp[slot] += n;
}

static void usage(const char *p)
{
    fprintf(stderr,
        "usage: sudo %s [-s slot] [-u] [-e type] [-d n] [-t] [-l]"
        " <iface> <gnb-mac>\n"
        "  -s <slot>  slot to analyse with the FFT, 0..19 (default 0)\n"
        "  -u         analyse the uplink instead of the downlink\n"
        "  -e <type>  ethertype, default 0xaefe\n"
        "  -d <n>     decimate the energy path\n"
        "  -t         timing mode: headers only, no energy, no grid\n"
        "  -l         per-frame log to stderr\n"
        "  e.g. sudo %s -s 0 sfp1 bc:24:11:ec:73:d3\n", p, p);
}

int main(int argc, char **argv)
{
    char err[PCAP_ERRBUF_SIZE];
    unsigned ethertype = 0xaefe;
    int opt;

    while ((opt = getopt(argc, argv, "s:ue:d:tlh")) != -1) {
        switch (opt) {
        case 's': g_slot = atoi(optarg);
                  if (g_slot < 0 || g_slot >= SLOTS_PER_FRAME) {
                      fprintf(stderr, "slot must be 0..19\n"); return 1; }
                  break;
        case 'u': g_grid_ul = 1; break;
        case 'e': ethertype = (unsigned)strtoul(optarg, NULL, 0); break;
        case 'd': g_decim = atoi(optarg); if (g_decim < 1) g_decim = 1; break;
        case 't': g_timing = 1; g_grid_on = 0; break;
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

    fft_init();
    reset_window(&g_dl);
    reset_window(&g_ul);

    g_ph = pcap_create(iface, err);
    if (!g_ph) { fprintf(stderr, "pcap_create: %s\n", err); return 1; }

    pcap_set_snaplen(g_ph, g_timing ? 64 : 65535);
    pcap_set_promisc(g_ph, 1);
    pcap_set_timeout(g_ph, 50);
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

    if (pcap_compile(g_ph, &fp, filter, 1, PCAP_NETMASK_UNKNOWN) < 0 ||
        pcap_setfilter(g_ph, &fp) < 0) {
        fprintf(stderr, "filter: %s\n", pcap_geterr(g_ph));
        return 1;
    }
    pcap_freecode(&fp);

    signal(SIGINT,  on_sigint);
    signal(SIGTERM, on_sigint);

    g_last_print = time(NULL);

    while (g_run) {
        int n = pcap_dispatch(g_ph, 256, on_packet, NULL);
        if (n == -1) {
            fprintf(stderr, "pcap_dispatch: %s\n", pcap_geterr(g_ph));
            break;
        }
        if (n == -2) break;

        time_t now = time(NULL);
        if (now != g_last_print) { g_last_print = now; draw(); }
    }

    draw();
    printf("\nstopped.\n");
    pcap_close(g_ph);
    return 0;
}
