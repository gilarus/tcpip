#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>

#include <linux/if.h>
#include <linux/if_tun.h>

#include <time.h>

#include <errno.h>

#include "tcpip.h"
#include "tapdev.h"

char *httperr = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 12\r\n\r\nHell, World!\r\n";
char *httpok  = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 13\r\n\r\nHello, World!\r\n";

#define CLOSED 0
#define LISTEN 1
#define SYN_SENT 2
#define SYN_RCVD 3
#define ESTABSD 4
#define FINWAIT_1 5
#define FINWAIT_2 6
#define CLOSE_WAIT 7
#define CLOSING 8
#define LAST_ACK 9
#define TIME_WAIT 10

#define IPv4_LEN 4
#define IP_HDR_LEN 20

#define IP_PKT_ID 0x0800
#define ARP_PKT_ID 0x0806
#define ETH_BASIC_FRAME_LEN (18) /* 12 2 4 */
#define ETH_FRAME_HDR_LEN (14) /* 12 2 */

int tcp;
uint32_t seq, ack, expectedack;

uint8_t tcpip_buf[ETH_BUF_MAX];
size_t tcpip_len;

uint8_t iphdrlen,
	tcphdrlen;

uint16_t tcppktlen,
	 ippktlen;

uint8_t ipaddr[IPv4_LEN];

char *httpdat;

#define sethostipaddr(x) memcpy(ipaddr, x, IPv4_LEN)
#define sethostmacaddr(x) memcpy(macaddr.mac, x, 6)

struct mac_address {
	uint8_t mac[6];
};

struct mac_address macaddr;

struct eth_header {
	uint8_t dstmac[6],
	srcmac[6],
	ethertype[2];
};

struct eth_header *ethptr = (struct eth_header *)tcpip_buf;

struct arp_header {
	uint8_t hrdtype[2],
	prototype[2],
	hrdlen,
	prolen,
	opcode[2],
	sndmac[6],
	sndip[IPv4_LEN],
	tgtmac[6],
	tgtip[IPv4_LEN];
};

struct arp_header *arpptr = (struct arp_header *)&tcpip_buf[14];

struct ip_header {
	uint8_t vhl,
	tos,
	/* endian */
	pktlen[2],
	identi[2],
	ffoffs[2],
	ttl,
	proto, /* TCP/UDP */
	csum[2],
	srcip[IPv4_LEN],
	dstip[IPv4_LEN];
};

struct ip_header *ipptr = (struct ip_header *)&tcpip_buf[14];

struct tcp_header {
	uint8_t srcport[2],
	dstport[2],
	seq[4],
	ack[4],
	datoffs,
	tcpflags,
	window[2],
	csum[2],
	urgprt[2];
};

struct tcp_header *tcpptr;

struct tcp_pseudo_header {
	uint8_t srcip[IPv4_LEN],
	dstip[IPv4_LEN],
	zero,
	ptcl,
	tcplen[2];
};

struct tcp_pseudo_header tcp_pseudo_hdr;

/*
 * packet of:
 * <dir >0: input 1: output
 * <type>0: IP 1: TCP
 */
uint16_t csum(int dir, int type)
{
	/* todo: padding */
	uint16_t csum = 0, v;
	uint8_t *ptr;
	size_t cnt, i;
	int chktcppseudo = 0;

#define reset_ip_csum() do { \
	ipptr->csum[0] = 0; \
	ipptr->csum[1] = 0; \
} while (0)
#define reset_tcp_csum() do { \
	tcpptr->csum[0] = 0; \
	tcpptr->csum[1] = 0; \
} while (0)
	if (type == 0) {
		ptr = (uint8_t *)ipptr;
		cnt = iphdrlen >> 1;
		if (dir == 1)
			reset_ip_csum();
	} else if (type == 1) {
		ptr = (uint8_t *)tcpptr;
		cnt = tcppktlen >> 1;
		chktcppseudo = 1;
		if (dir == 1)
			reset_tcp_csum();
	} else
		return 0xffff;
ca:
	for (i = 0; i < cnt; i++) {
		/* todo v = ntoh16(ptr);*/
		v = *ptr << 8;
		ptr++;
		v += *ptr;
		ptr++;
		csum += v;
		if (csum < v)
			csum++;/* carry */
	}
	if (type == 1 && chktcppseudo) {
		chktcppseudo = 0;
		ptr = (uint8_t *)&tcp_pseudo_hdr;
		cnt = 6; /* 96bits */
		goto ca;
	}
	csum = ~csum;
#define set_ip_csum(x) do { \
	ipptr->csum[0] = x >> 8; \
	ipptr->csum[1] = x; \
} while (0)
#define set_tcp_csum(x) do { \
	tcpptr->csum[0] = x >> 8; \
	tcpptr->csum[1] = x; \
} while (0)
	if (dir == 1) {
		if (type == 0)
			set_ip_csum(csum);
		else if (type == 1)
			set_tcp_csum(csum);
	}
	return csum;
}
#define h16ton8(_16,_88) do { \
	*_88 = _16 >> 8; \
	*(_88 + 1) = _16; \
} while (0)
#define h32ton8(_32,_8888) do { \
	*_8888 = _32 >> 24; \
	*(_8888 + 1) = _32 >> 16; \
	*(_8888 + 2) = _32 >> 8; \
	*(_8888 + 3) = _32; \
} while (0)
#define ntoh16(px) (*px << 8 | *(px + 1))
#define ntoh32(px) (*px << 24 | *(px + 1) << 16 | \
		*(px + 2) << 8 | *(px + 3))
int main(void)
{
	uint8_t ip[IPv4_LEN] = {10, 0, 0, 2};
	int drops = 0;
	uint16_t ethertype;

	sethostipaddr(ip);

	tapdev_init(NULL);
	tapdev_test();

	tcp = LISTEN;
	seq = 81;
	expectedack = 0;

rcvd:
	memset(tcpip_buf, 0x0, tcpip_len);

	tcpip_len = tapdev_read();

	if (tcpip_len < 34)
		goto drop;

	ethertype = ntoh16(ethptr->ethertype);
	if (ethertype == IP_PKT_ID)
		goto ippktid;
	else if (ethertype == ARP_PKT_ID)
		goto arppktid;
	else {
		puts("\runknown packet id");
		goto drop;
	}
arppktid:
	if (ntoh16(arpptr->hrdtype) != 0x01)
		goto drop;
	if (arpptr->hrdlen != 6)
		goto drop;
	if (ntoh16(arpptr->prototype) != IP_PKT_ID)
		goto drop;
	if (arpptr->prolen != 4)
		goto drop;
	/* Am I the target protocol address? */
	if (memcmp(arpptr->tgtip, ipaddr, IPv4_LEN) != 0)
		goto drop;

	sethostmacaddr(arpptr->sndmac);

#define ARP_REQUEST 0x01
#define ARP_REPLY 0x02

	if (arpptr->opcode[1] == ARP_REQUEST) {
		/* Swap mac&ip */
		memcpy(arpptr->tgtmac, arpptr->sndmac, 6);
		memcpy(arpptr->sndmac, macaddr.mac, 6);
		memcpy(arpptr->tgtip, arpptr->sndip, IPv4_LEN);
		memcpy(arpptr->sndip, ipaddr, IPv4_LEN);
		arpptr->opcode[1] = ARP_REPLY;
		/* pkt len was the same */
		tapdev_send();
	}
	goto rcvd;

ippktid:
	if (ipptr->vhl != 0x45)
		goto drop;

	ippktlen = ntoh16(ipptr->pktlen);

#define switch_ipaddrs() do { \
	uint8_t tmp; \
	int i; \
	for (i = 0; i < IPv4_LEN; i++) { \
		tmp = ipptr->srcip[i]; \
		ipptr->srcip[i] = ipptr->dstip[i]; \
		ipptr->dstip[i] = tmp; \
	} \
} while (0)
	/* is this for me? */
	if (memcmp(ipptr->dstip, ipaddr, IPv4_LEN) == 0)
		switch_ipaddrs();

	iphdrlen = (ipptr->vhl & 0xf) << 2;
	tcppktlen = ippktlen - iphdrlen;

	if (csum(0, 0) != 0)
		goto drop;

	tcpptr = (struct tcp_header *)&tcpip_buf[iphdrlen + ETH_FRAME_HDR_LEN];
	
	/* Prepare tcp pseudo header */
	/* srcip&dstip was switched, but that's ok! */
	memcpy(tcp_pseudo_hdr.srcip, ipptr->srcip, IPv4_LEN);
	memcpy(tcp_pseudo_hdr.dstip, ipptr->dstip, IPv4_LEN);
	tcp_pseudo_hdr.zero = 0;
	tcp_pseudo_hdr.ptcl = 6; /* TCP Protocol */

	h16ton8(tcppktlen, tcp_pseudo_hdr.tcplen);
	if (csum(0, 1) != 0)
		goto drop;
	if (tcpptr->srcport[3] != 80)
		goto drop;
	/* switch ports */
#define switch_ports() do { \
	uint8_t tmp; \
	int i; \
	for (i = 0; i < 2; ++i) {\
		tmp = tcpptr->srcport[i];\
		tcpptr->srcport[i] = tcpptr->dstport[i]; \
		tcpptr->dstport[i] = tmp; \
	} \
} while (0)
	switch_ports();

	/* TCP State */
#define FLG_URG 0x20
#define FLG_ACK 0x10
#define FLG_PSH 0x08
#define FLG_RST 0x04
#define FLG_SYN 0x02
#define FLG_FIN 0x01
	switch(tcp) {
	case CLOSED:
		break;
	case LISTEN:
		/* rcv SYN */
		if (tcpptr->tcpflags != FLG_SYN)
			goto drop;
		/* snd SYN,ACK */
		tcpptr->tcpflags = FLG_SYN|FLG_ACK;
		tcp = SYN_RCVD;
		ack = ntoh32(tcpptr->seq) + 1;
		expectedack = seq + 1;
		break;
	case SYN_RCVD:
		/* rcv SYN again! */
		if (tcpptr->tcpflags == FLG_SYN) {
			/* snd SYN,ACK */
			goto drop;
		}
		/* rcv ACK of SYN */
		if (tcpptr->tcpflags != FLG_ACK)
			goto drop;
		if (ntoh32(tcpptr->ack) != expectedack)
			goto drop;
		tcp = ESTABSD;
		/* *(do not send anything) */
		goto rcvd;
		break;
	case SYN_SENT:
		break;
	case ESTABSD:
		/* rcv FIN */
		if (tcpptr->tcpflags & FLG_FIN) {
			/* snd ACK */
			tcpptr->tcpflags = FLG_ACK;
			seq = ntoh32(tcpptr->ack);
			ack = ntoh32(tcpptr->seq) + 1;
			tcp = CLOSE_WAIT;
			tapdev_send();
			goto close_wait;
		}
		/* Handling Http data */
		if (tcpptr->tcpflags == FLG_ACK) {
			/* Ack of my response */
			if (expectedack == ntoh32(tcpptr->ack)) {
				/* maybe send a FIN? */
			}
		}
		if (tcpptr->tcpflags != (FLG_PSH|FLG_ACK))
			goto rcvd;

		/* Prepare reply */
		tcphdrlen = ((tcpptr->datoffs&0xF0) >> 4) << 2;
		uint16_t httpdatlen;
		httpdatlen = tcppktlen - tcphdrlen;
		httpdat = &tcpip_buf[tcphdrlen + iphdrlen + ETH_FRAME_HDR_LEN];
		if (strncmp(httpdat, "GET /", 5) != 0)
			strcpy(httpdat, httperr);
		else
			strcpy(httpdat, httpok);
		ack = ntoh32(tcpptr->seq) + httpdatlen;
		httpdatlen = strlen(httpdat) + 1; /* \0 */
		seq = ntoh32(tcpptr->ack);
		expectedack = seq + httpdatlen;
		tcpptr->tcpflags = FLG_ACK;
		tcppktlen = tcphdrlen + httpdatlen;
		ippktlen = tcppktlen + iphdrlen;
		tcpip_len = ippktlen + ETH_BASIC_FRAME_LEN;
		break;
	case FINWAIT_1:
		break;
	case FINWAIT_2:
		break;
	case CLOSE_WAIT:
close_wait:
		/* snd FIN,ACK */
		tcpptr->tcpflags = FLG_FIN|FLG_ACK;
		tcp = LAST_ACK;
		break;
	case CLOSING:
		break;
	case LAST_ACK:
		if (tcpptr->tcpflags == FLG_ACK)
			goto rcvd;
		if (ntoh32(tcpptr->seq) != ack)
			goto rcvd;
		if (ntoh32(tcpptr->ack) != seq)
			goto rcvd;
		tcp = CLOSED;

		break;
	case TIME_WAIT:
		break;
	}
	/* Update tcp pseudo header */
	h16ton8(tcppktlen, tcp_pseudo_hdr.tcplen);

	/* Update seq, ack */
	h32ton8(seq, tcpptr->seq);
	h32ton8(ack, tcpptr->ack);

	/* Update ip pkt len */
	h16ton8(ippktlen, ipptr->pktlen);

	/* TCP csum */
	csum(1, 1);
	/* IP csum */
	csum(1, 0);

	tapdev_send();

	goto rcvd;
drop:
	drops++;
	printf("\r	");
	printf("\rerror packet: %d", drops);
	goto rcvd;

	return 0;
}
