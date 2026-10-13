/* -------------------------------------------------------------------------
 * live7.c - live Split 8 fronthaul display with a whole-frame survey
 *
 * Default mode walks every slot in turn, in both directions, and prints
 * one line per occupied slot: which symbols carry energy and across which
 * resource blocks. A complete picture of the frame about once a second.
 *
 *   gcc -O3 -march=native -o live7 live7.c -lpcap -lm
 *   sudo ./live7 sfp1 bc:24:11:ec:73:d3
 *
 * With -s it locks to one slot and draws the full 14 x 273 grid instead,
 * averaged over frames, which is what live6 did.
 *
 *   sudo ./live7 -s 10 sfp1 bc:24:11:ec:73:d3
 *
 * Options
 *   -s <slot>       lock to one slot and draw the full grid
 *   -u              with -s, analyse the uplink instead of the downlink
 *   -e <ethertype>  default 0xaefe
 *   -d <n>          decimate the energy path
 *   -t              timing mode: headers only, no energy, no FFT
 *   -l              per-frame log to stderr
 *
 * Why rotating costs no more than one slot
 *
 *   Buffering the whole frame would mean copying all 640 packets, which is
 *   986 MB/s of extra memory traffic - the mistake that cost 90% of the
 *   link in an earlier version. Rotating copies 32 packets per direction
 *   per frame, the same as analysing a single slot, and still covers all
 *   twenty because a different one is buffered each time.
 *
 *   A slot is only transformed when all 32 of its packets arrived, and a
 *   slot reading below -110 dBFS is skipped without an FFT at all. On a
 *   quiet cell that is 5 slots of 20.
 *
 * Numerology, mu = 1, 273 PRB, 122.88 Msps
 *
 *   FFT 4096, 14 symbols, CP 352 on symbol 0 and 288 on the rest
 *   352 + 13*288 + 14*4096 = 61440 = one slot exactly
 *   PRB k covers subcarriers -1638 + 12k .. +11, PRB 136 on DC
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
#define QUIET_DB         (-110.0)      /* below this, do not bother with an FFT */
#define BARW               24
#define WRAP_MIN         (PKTS_PER_FRAME / 2)

#define NFFT             4096
#define NSYM               14
#define CP0               352
#define CP                288
#define NPRB              273
#define SC_PER_PRB         12
#define SC_FIRST        (-1638)
#define SLOT_SAMPLES    61440
#define GRID_COLS          91
#define PRB_PER_COL         3
#define ANALYSE_GAP         5          /* frames between transforms */

/* ---- FFT -------------------------------------------------------------- */

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
        int half = len >> 1, step = NFFT / len;
        for (int i = 0; i < NFFT; i += len)
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

/* ---- per-slot capture and summary ------------------------------------- */

typedef struct {
    int16_t  buf[SLOT_SAMPLES * 2];
    uint8_t  seen[PKTS_PER_SLOT];
    int      slot;                 /* slot currently being buffered */
    uint64_t next_fno;             /* earliest frame allowed to transform */
} grab_t;

typedef struct {
    int      valid;
    uint32_t symmask;
    int      prb_lo, prb_hi, prb_n;
    double   peak_rel;             /* dB of this slot's strongest PRB */
} summ_t;

static grab_t g_grab[2];                      /* 0 = DL, 1 = UL */
static summ_t g_sum[2][SLOTS_PER_FRAME];

static double g_fgrid[NSYM][NPRB];            /* one frame's grid */
static double g_agrid[NSYM][NPRB];            /* accumulated, locked mode */
static uint32_t g_agrid_n;

static int g_lock_slot = -1;                  /* -1 = rotate */
static int g_lock_ul   = 0;
static int g_grid_on   = 1;

/* transform the buffered slot into g_fgrid */
static void transform(const int16_t *buf)
{
    int off = 0;
    for (int sym = 0; sym < NSYM; sym++) {
        off += (sym == 0) ? CP0 : CP;

        for (int i = 0; i < NFFT; i++) {
            g_re[i] = (float)buf[2 * (off + i)];
            g_im[i] = (float)buf[2 * (off + i) + 1];
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
            g_fgrid[sym][k] = p;
        }
        off += NFFT;
    }
}

/* reduce one frame's grid to a one-line summary */
static void summarise(summ_t *o)
{
    double peak = 0.0;
    for (int s = 0; s < NSYM; s++)
        for (int k = 0; k < NPRB; k++)
            if (g_fgrid[s][k] > peak) peak = g_fgrid[s][k];

    memset(o, 0, sizeof *o);
    if (peak <= 0.0) return;

    double thr = peak * 0.01;              /* 20 dB below this slot's peak */
    int lo = NPRB, hi = -1, widest = 0;

    for (int s = 0; s < NSYM; s++) {
        int n = 0, a = -1, b = -1;
        for (int k = 0; k < NPRB; k++)
            if (g_fgrid[s][k] >= thr) { if (a < 0) a = k; b = k; n++; }
        if (n == 0) continue;
        o->symmask |= (1u << s);
        if (a < lo) lo = a;
        if (b > hi) hi = b;
        if (n > widest) widest = n;
    }
    if (hi < 0) return;

    o->valid  = 1;
    o->prb_lo = lo;
    o->prb_hi = hi;
    o->prb_n  = widest;
}

/* "0,2-11" */
static void render_syms(uint32_t m, char *out, size_t n)
{
    size_t p = 0;
    out[0] = '\0';
    for (int s = 0; s < NSYM; ) {
        if (!(m & (1u << s))) { s++; continue; }
        int a = s;
        while (s < NSYM && (m & (1u << s))) s++;
        int b = s - 1;
        int w = (a == b) ? snprintf(out + p, n - p, "%s%d", p ? "," : "", a)
                         : snprintf(out + p, n - p, "%s%d-%d", p ? "," : "", a, b);
        if (w < 0 || (size_t)w >= n - p) return;
        p += (size_t)w;
    }
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
    uint64_t    pkts, frames, partial, fno;
} dir_t;

static dir_t g_dl = { "DL", 'D' };
static dir_t g_ul = { "UL", 'U' };

static pcap_t  *g_ph;
static uint8_t  g_gnb[6];
static uint64_t g_bad, g_trunc, g_reorder;
static uint32_t g_prev_drop, g_prev_ifdrop;
static time_t   g_last_print;
static volatile sig_atomic_t g_run = 1;

static int g_decim = 1, g_timing = 0, g_log = 0;

static void on_sigint(int s)
{
    (void)s; g_run = 0;
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
    int    di = (d == &g_dl) ? 0 : 1;

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

    if (g_grid_on) {
        grab_t *g  = &g_grab[di];
        int     sl = g->slot;
        int     mine = (g_lock_slot < 0) ? 1
                     : (sl == g_lock_slot && di == (g_lock_ul ? 1 : 0));

        if (mine && d->fno >= g->next_fno) {
            if (cur[sl] <= QUIET_DB) {
                memset(&g_sum[di][sl], 0, sizeof g_sum[di][sl]);
                g->next_fno = d->fno + 1;          /* nothing to transform */
            } else {
                uint32_t got = 0;
                for (int i = 0; i < PKTS_PER_SLOT; i++) got += g->seen[i];
                if (got == PKTS_PER_SLOT) {
                    transform(g->buf);
                    summarise(&g_sum[di][sl]);
                    if (g_lock_slot >= 0) {
                        for (int s = 0; s < NSYM; s++)
                            for (int k = 0; k < NPRB; k++)
                                g_agrid[s][k] += g_fgrid[s][k];
                        g_agrid_n++;
                    }
                    g->next_fno = d->fno + ANALYSE_GAP;
                }
            }
            if (g_lock_slot < 0 && d->fno >= g->next_fno - ANALYSE_GAP)
                g->slot = (g->slot + 1) % SLOTS_PER_FRAME;
        }
        memset(g->seen, 0, sizeof g->seen);
    }

    d->fno++;
    memset(d->seen, 0, sizeof d->seen);
    d->frames++;
}

static void reset_window(dir_t *d)
{
    for (uint32_t s = 0; s < SLOTS_PER_FRAME; s++) d->peak[s] = SILENT_DB;
    d->cells_max = 0;
    d->cells_min = PKTS_PER_FRAME;
    d->frames = d->partial = d->pkts = 0;
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

static void draw_survey(void)
{
    printf("\n  slot  dir   dBFS    symbols          PRB span     width\n");
    for (int s = 0; s < SLOTS_PER_FRAME; s++)
        for (int di = 0; di < 2; di++) {
            dir_t *d = di ? &g_ul : &g_dl;
            if (d->peak[s] <= QUIET_DB) continue;
            summ_t *u = &g_sum[di][s];
            char syms[40] = "-";
            if (u->valid) render_syms(u->symmask, syms, sizeof syms);
            if (u->valid)
                printf("   %2d   %s   %6.1f    %-14s   %3d..%-3d     %3d\n",
                       s, di ? "UL" : "DL", d->peak[s], syms,
                       u->prb_lo, u->prb_hi, u->prb_n);
            else
                printf("   %2d   %s   %6.1f    %-14s\n",
                       s, di ? "UL" : "DL", d->peak[s], "waiting");
        }
    printf("  symbols and PRB from a complete copy of that slot;"
           " all twenty are walked in turn\n");
}

static void draw_grid(void)
{
    printf("\n  resource grid   slot %d   %s   %u frames\n",
           g_lock_slot, g_lock_ul ? "UL" : "DL", g_agrid_n);

    if (g_agrid_n == 0) { printf("  no complete copy of that slot yet\n"); return; }

    double peak = 0.0;
    for (int s = 0; s < NSYM; s++)
        for (int k = 0; k < NPRB; k++)
            if (g_agrid[s][k] > peak) peak = g_agrid[s][k];

    if (peak <= 0.0) {
        printf("  slot is empty - every subcarrier reads zero\n");
        memset(g_agrid, 0, sizeof g_agrid); g_agrid_n = 0; return;
    }

    printf("  sym  PRB 0%*s%d\n", GRID_COLS - 10, "", NPRB - 1);
    for (int s = 0; s < NSYM; s++) {
        char row[GRID_COLS + 1];
        for (int c = 0; c < GRID_COLS; c++) {
            double m = 0.0;
            for (int j = 0; j < PRB_PER_COL; j++) {
                int k = c * PRB_PER_COL + j;
                if (k < NPRB && g_agrid[s][k] > m) m = g_agrid[s][k];
            }
            row[c] = (m > 0.0) ? level_char(10.0 * log10(m / peak)) : ' ';
        }
        row[GRID_COLS] = '\0';
        printf("  %3d  |%s|\n", s, row);
    }

    double thr = peak * 0.01;
    printf("\n  occupied PRB, 20 dB below peak:\n");
    for (int s = 0; s < NSYM; s++) {
        int lo = -1, hi = -1, n = 0;
        for (int k = 0; k < NPRB; k++)
            if (g_agrid[s][k] >= thr) { if (lo < 0) lo = k; hi = k; n++; }
        if (lo < 0) continue;
        printf("    sym %2d   PRB %3d..%3d   %3d PRB\n", s, lo, hi, n);
    }
    printf("  key  @ %% # * + = - : .   strongest to 50 dB down\n");

    memset(g_agrid, 0, sizeof g_agrid);
    g_agrid_n = 0;
}

static void draw(void)
{
    struct pcap_stat st;
    uint32_t d_drop = 0, d_ifdrop = 0;

    if (g_ph && pcap_stats(g_ph, &st) == 0) {
        d_drop   = st.ps_drop   - g_prev_drop;
        d_ifdrop = st.ps_ifdrop - g_prev_ifdrop;
        g_prev_drop = st.ps_drop;  g_prev_ifdrop = st.ps_ifdrop;
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

    if (!g_grid_on) {
        printf("\n  slot    DL dBFS    UL dBFS\n");
        for (uint32_t s = 0; s < SLOTS_PER_FRAME; s++) {
            if (g_dl.peak[s] <= SILENT_DB && g_ul.peak[s] <= SILENT_DB) continue;
            char bd[BARW + 1], bu[BARW + 1];
            bar(bd, g_dl.peak[s]); bar(bu, g_ul.peak[s]);
            printf("   %2u   |%s| %6.1f   |%s| %6.1f\n",
                   s, bd, g_dl.peak[s], bu, g_ul.peak[s]);
        }
    } else if (g_lock_slot < 0) {
        draw_survey();
    } else {
        printf("\n  slot    DL dBFS    UL dBFS\n");
        for (uint32_t s = 0; s < SLOTS_PER_FRAME; s++) {
            if (g_dl.peak[s] <= SILENT_DB && g_ul.peak[s] <= SILENT_DB) continue;
            char bd[BARW + 1], bu[BARW + 1];
            bar(bd, g_dl.peak[s]); bar(bu, g_ul.peak[s]);
            printf("   %2u   |%s| %6.1f   |%s| %6.1f\n",
                   s, bd, g_dl.peak[s], bu, g_ul.peak[s]);
        }
        draw_grid();
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

    int is_dl  = (memcmp(bytes + 6, g_gnb, 6) == 0);
    int di     = is_dl ? 0 : 1;
    dir_t *d   = is_dl ? &g_dl : &g_ul;
    uint32_t cell = (uint32_t)seq - 1;

    if (d->started && cell < d->last_cell) {
        if (d->last_cell - cell > WRAP_MIN) finish_frame(d);
        else                                g_reorder++;
    }
    d->started = 1;
    d->last_cell = cell;
    d->pkts++;
    d->seen[cell] = 1;

    if (g_timing) return;
    if (h->caplen < ETH_HDR + ECPRI_HDR_SIZE + IQ_BYTES) { g_trunc++; return; }

    const int16_t *iq = (const int16_t *)(b + ECPRI_HDR_SIZE);
    uint32_t slot = cell / PKTS_PER_SLOT;

    /* 32 packets of 640 are copied, whichever slot is being walked now */
    if (g_grid_on && (int)slot == g_grab[di].slot) {
        uint32_t idx = cell % PKTS_PER_SLOT;
        memcpy(&g_grab[di].buf[idx * SAMPLES_PER_PKT * 2], iq, IQ_BYTES);
        g_grab[di].seen[idx] = 1;
    }

    uint64_t acc = 0, n = 0;
    for (int i = 0; i < SAMPLES_PER_PKT; i += g_decim) {
        int64_t I = iq[2 * i], Q = iq[2 * i + 1];
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
        "  (no -s)    walk every slot, one summary line each\n"
        "  -s <slot>  lock to one slot and draw the full grid\n"
        "  -u         with -s, analyse the uplink\n"
        "  -e <type>  ethertype, default 0xaefe\n"
        "  -d <n>     decimate the energy path\n"
        "  -t         timing mode: headers only, no FFT\n"
        "  -l         per-frame log to stderr\n"
        "  e.g. sudo %s sfp1 bc:24:11:ec:73:d3\n", p, p);
}

int main(int argc, char **argv)
{
    char err[PCAP_ERRBUF_SIZE];
    unsigned ethertype = 0xaefe;
    int opt;

    while ((opt = getopt(argc, argv, "s:ue:d:tlh")) != -1) {
        switch (opt) {
        case 's': g_lock_slot = atoi(optarg);
                  if (g_lock_slot < 0 || g_lock_slot >= SLOTS_PER_FRAME) {
                      fprintf(stderr, "slot must be 0..19\n"); return 1; }
                  break;
        case 'u': g_lock_ul = 1; break;
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

    if (g_lock_slot >= 0) {
        g_grab[0].slot = g_grab[1].slot = g_lock_slot;
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
        fprintf(stderr, "%s is not Ethernet\n", iface); return 1;
    }

    char filter[64];
    struct bpf_program fp;
    snprintf(filter, sizeof filter, "ether proto 0x%04x", ethertype);
    if (pcap_compile(g_ph, &fp, filter, 1, PCAP_NETMASK_UNKNOWN) < 0 ||
        pcap_setfilter(g_ph, &fp) < 0) {
        fprintf(stderr, "filter: %s\n", pcap_geterr(g_ph)); return 1;
    }
    pcap_freecode(&fp);

    signal(SIGINT,  on_sigint);
    signal(SIGTERM, on_sigint);

    g_last_print = time(NULL);

    while (g_run) {
        int n = pcap_dispatch(g_ph, 256, on_packet, NULL);
        if (n == -1) { fprintf(stderr, "pcap_dispatch: %s\n",
                               pcap_geterr(g_ph)); break; }
        if (n == -2) break;

        time_t now = time(NULL);
        if (now != g_last_print) { g_last_print = now; draw(); }
    }

    draw();
    printf("\nstopped.\n");
    pcap_close(g_ph);
    return 0;
}
