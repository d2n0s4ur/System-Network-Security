#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <netinet/in.h>

#include "pcap-test.h"

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) { // Error while get PCD(Packet Capture Descriptor)
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) { // get PCD success
		struct pcap_pkthdr*	header;
		const u_char*		packet;
		t_ethernet_hdr		*ether;
		t_ipv4_hdr			*ipv4;
		t_tcp_hdr			*tcp;
		
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		ether = (t_ethernet_hdr *)(packet);
		if (ether->ether_type != ETH_TYPE_IPV4) continue; // check ipv4
		ipv4 = (t_ipv4_hdr *)(packet + sizeof(*ether));
		if(ipv4->ip_prot != IPV4_PROT_TCP) continue; // check tcp
		tcp = (t_tcp_hdr *)(packet + sizeof(*ether) + sizeof(*ipv4));

		printf("==========[ETHERNET PACKET]==========\n");
		printf("src mac: ");
		print_mac_addr(ether->mac_src_addr);
		printf("\ndst mac: ");
		print_mac_addr(ether->mac_dst_addr);
		printf("\n=============[IP PACKET]=============\n");
		printf("src ip: ");
		print_ip_addr(ipv4->ip_src);
		printf("\ndst ip: ");
		print_ip_addr(ipv4->ip_dst);
		printf("\n=============[TCP PACKET]============\n");
		printf("src port: %u\ndst port: %u\n",ntohs(tcp->tcp_src_port), ntohs(tcp->tcp_dst_port));
		printf("payload: ");
		int payload_offset = sizeof(*ether) + sizeof(*ipv4) + tcp->tcp_offset * 4;
		print_payload(packet + payload_offset, header->caplen - payload_offset);
		printf("\n\n");
	}

	pcap_close(pcap);
}
