#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <pcap.h>

#define ETH_HDR  14

static pcap_t        *g_ph;
static pcap_dumper_t *g_match_out, *g_other_out;
static uint8_t        g_mac[6];
static uint64_t       g_match, g_other, g_short;

static void on_sigint(int s) { (void)s; if (g_ph) pcap_breakloop(g_ph); }

static int parse_mac(const char *s, uint8_t m[6])
{
    return sscanf(s, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                  &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]) == 6 ? 0 : -1;
}

static void on_packet(unsigned char *user,
                      const struct pcap_pkthdr *h,
                      const unsigned char *bytes)
{
    (void)user;
    if (h->caplen < ETH_HDR) { g_short++; return; }

    if (memcmp(bytes + 6, g_mac, 6) == 0) {
        pcap_dump((unsigned char *)g_match_out, h, bytes);
        g_match++;
    } else {
        pcap_dump((unsigned char *)g_other_out, h, bytes);
        g_other++;
    }
}

static void usage(const char *prog)
{
    fprintf(stderr,
      "usage: sudo %s <iface> <src-mac> [ethertype] [count]\n"
      "\n"
      "  Captures from <iface> and writes every frame to one of two files,\n"
      "  chosen by the frame's source MAC address.\n"
      "\n"
      "    match.pcap   source MAC == <src-mac>\n"
      "    other.pcap   everything else\n"
      "\n"
      "  ethertype  hex, e.g. 0x0800. omit to capture all frames\n"
      "  count      stop after N packets. omit to run until Ctrl-C\n"
      "\n"
      "  e.g. sudo %s eth0 aa:bb:cc:dd:ee:ff 0x0800 100000\n", prog, prog);
}

int main(int argc, char **argv)
{
    char err[PCAP_ERRBUF_SIZE];

    if (argc < 3) { usage(argv[0]); return 1; }

    if (parse_mac(argv[2], g_mac) != 0) {
        fprintf(stderr, "bad MAC: %s\n", argv[2]);
        return 1;
    }

    unsigned ethertype = (argc > 3) ? (unsigned)strtoul(argv[3], NULL, 0) : 0;
    int      count     = (argc > 4) ? atoi(argv[4]) : 0;

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

    if (pcap_datalink(g_ph) != DLT_EN10MB) {
        fprintf(stderr, "%s is not Ethernet\n", argv[1]);
        return 1;
    }

    if (ethertype) {
        char filter[64];
        struct bpf_program fp;
        snprintf(filter, sizeof filter, "ether proto 0x%04x", ethertype);

        if (pcap_compile(g_ph, &fp, filter, 1, PCAP_NETMASK_UNKNOWN) < 0 ||
            pcap_setfilter(g_ph, &fp) < 0) {
            fprintf(stderr, "filter: %s\n", pcap_geterr(g_ph));
            return 1;
        }
        pcap_freecode(&fp);
        fprintf(stderr, "filter: %s\n", filter);
    }

    g_match_out = pcap_dump_open(g_ph, "match.pcap");
    g_other_out = pcap_dump_open(g_ph, "other.pcap");
    if (!g_match_out || !g_other_out) {
        fprintf(stderr, "dump_open: %s\n", pcap_geterr(g_ph));
        return 1;
    }

    signal(SIGINT, on_sigint);
    fprintf(stderr, "capturing on %s -> match.pcap / other.pcap", argv[1]);
    if (count) fprintf(stderr, ", stopping after %d packets\n", count);
    else       fprintf(stderr, ".  Ctrl-C to stop.\n");

    pcap_loop(g_ph, count, on_packet, NULL);

    pcap_dump_close(g_match_out);
    pcap_dump_close(g_other_out);

    struct pcap_stat st;
    pcap_stats(g_ph, &st);
    printf("\nmatch=%lu  other=%lu  short=%lu   recv=%u drop=%u ifdrop=%u\n",
           (unsigned long)g_match, (unsigned long)g_other,
           (unsigned long)g_short, st.ps_recv, st.ps_drop, st.ps_ifdrop);

    pcap_close(g_ph);
    return 0;
}
