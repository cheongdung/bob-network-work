#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <libnet.h>
#include <netinet/in.h>

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
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		
		if (header->caplen < sizeof(struct libnet_ethernet_hdr))  
	    continue; 
	  	struct libnet_ethernet_hdr* eth = (struct libnet_ethernet_hdr*)packet; 
	  
	  	if (ntohs(eth->ether_type) != ETHERTYPE_IP)
		  continue; //ipv4일때만!
		 
		
		//mac 
		printf("%u bytes captured\n", header->caplen);
		
		printf("src mac: %02x:%02x:%02x:%02x:%02x:%02x\n",
        eth->ether_shost[0],
        eth->ether_shost[1],
        eth->ether_shost[2],
        eth->ether_shost[3],
        eth->ether_shost[4],
        eth->ether_shost[5]);
		
		printf("dst mac: %02x:%02x:%02x:%02x:%02x:%02x\n",
        eth->ether_dhost[0],
        eth->ether_dhost[1],
        eth->ether_dhost[2],
        eth->ether_dhost[3],
        eth->ether_dhost[4],
        eth->ether_dhost[5]);
		
		
		//ip
		if (header->caplen < sizeof(struct libnet_ethernet_hdr) + sizeof(struct libnet_ipv4_hdr))
			continue;

		struct libnet_ipv4_hdr* ip = (struct libnet_ipv4_hdr*)(packet + sizeof(struct libnet_ethernet_hdr));
		uint8_t ip_header_len = ip->ip_hl * 4;

		if (ip_header_len < sizeof(struct libnet_ipv4_hdr))
		    continue;

		if (header->caplen < sizeof(struct libnet_ethernet_hdr) + ip_header_len)
		    continue;
		    
		if(ip->ip_p != IPPROTO_TCP)
				continue;
		
		uint32_t src_ip = ntohl(ip->ip_src.s_addr);

		printf("src ip: %u.%u.%u.%u\n",
        (unsigned)((src_ip >> 24) & 0xFF),
        (unsigned)((src_ip >> 16) & 0xFF),
        (unsigned)((src_ip >> 8) & 0xFF),
        (unsigned)(src_ip & 0xFF));
		
		uint32_t dst_ip = ntohl(ip->ip_dst.s_addr);

		printf("dst ip: %u.%u.%u.%u\n",
        (unsigned)((dst_ip >> 24) & 0xFF),
        (unsigned)((dst_ip >> 16) & 0xFF),
        (unsigned)((dst_ip >> 8) & 0xFF),
        (unsigned)(dst_ip & 0xFF));   
    
    	//port
    	if (header->caplen < sizeof(struct libnet_ethernet_hdr) + ip_header_len + sizeof(struct libnet_tcp_hdr))
		    continue;
		
		struct libnet_tcp_hdr* tcp = (struct libnet_tcp_hdr*)(packet + sizeof(struct libnet_ethernet_hdr) + ip_header_len);
		
		
  		uint16_t src_port = ntohs(tcp->th_sport);
    	printf("src port: %u\n", src_port);
    	uint16_t dst_port = ntohs(tcp->th_dport);
    	printf("dst port: %u\n", dst_port);

		
		//payload (시작점을 찾기 위해 tcp 헤더의 실제 길이 구해야함)
		uint8_t tcp_header_len = tcp->th_off * 4;
		if (tcp_header_len < sizeof(struct libnet_tcp_hdr))
    		continue;

		if (header->caplen < sizeof(struct libnet_ethernet_hdr) + ip_header_len + tcp_header_len)
		    continue;
		 
		const u_char* payload = (const u_char*)tcp + tcp_header_len;

		int payload_len = ntohs(ip->ip_len) - ip_header_len - tcp_header_len;

		if (payload_len < 0)
		    continue;

		int captured_len = header->caplen - (payload - packet);

		if (payload_len > captured_len)
				payload_len = captured_len;

		int print_len = payload_len > 20 ? 20 : payload_len;

		printf("data: ");
		
		for (int i = 0; i < print_len; i++)
		    printf("%02x ", payload[i]);
		
		printf("\n");
		 
	}

	pcap_close(pcap);
}
