#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>
#include <pcap.h>

#define ETH_HDR         14
#define ECPRI_HDR_SIZE   8
#define PKTS_PER_SLOT   32

static uint64_t g_ok, g_bad[8];

static void on_packet(unsigned char *user,
                      const struct pcap_pkthdr *h,
                      const unsigned char *bytes)
{
    (void)user;

    if (h->caplen < ETH_HDR + ECPRI_HDR_SIZE) { g_bad[1]++; return; }

    const uint8_t *b = bytes + ETH_HDR;

    uint8_t version  = (b[0] >> 4) & 0x0F;
    uint8_t msg_type = b[1];

    if (version  != 1)    { g_bad[2]++; return; }
    if (msg_type != 0x00) { g_bad[3]++; return; }

    uint16_t v;
    uint16_t payload, pc_id, seq_id;
    memcpy(&v, b + 2, 2);  payload = ntohs(v);
    memcpy(&v, b + 4, 2);  pc_id   = ntohs(v);
    memcpy(&v, b + 6, 2);  seq_id  = ntohs(v);

    if (seq_id < 1 || seq_id > 0x280) { g_bad[4]++; return; }

    uint32_t cell = (uint32_t)seq_id - 1;
    uint32_t slot = cell / PKTS_PER_SLOT;
    const int16_t *iq = (const int16_t *)(b + ECPRI_HDR_SIZE);

    (void)pc_id;

    if (g_ok < 20)
        printf("seq=%4u cell=%3u slot=%2u payload=%u caplen=%u iq[0]=%d %d\n",
               seq_id, cell, slot, payload, h->caplen, iq[0], iq[1]);

    g_ok++;
}

int main(int argc, char **argv)
{
    char err[PCAP_ERRBUF_SIZE];

    if (argc < 2) { fprintf(stderr, "usage: %s <file.pcap>\n", argv[0]); return 1; }

    pcap_t *ph = pcap_open_offline(argv[1], err);
    if (!ph) { fprintf(stderr, "%s\n", err); return 1; }

    pcap_loop(ph, 0, on_packet, NULL);
    pcap_close(ph);

    printf("\nok=%lu  short=%lu  bad_version=%lu  bad_type=%lu  bad_seq=%lu\n",
           (unsigned long)g_ok, (unsigned long)g_bad[1],
           (unsigned long)g_bad[2], (unsigned long)g_bad[3],
           (unsigned long)g_bad[4]);
    return 0;
}
