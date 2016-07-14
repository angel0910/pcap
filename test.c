#define LIBNET_LIL_ENDIAN 1

#include <stdio.h>
#include <pcap.h>
#include <stdint.h>
#include <unistd.h>
#include <libnet.h>
#include <arpa/inet.h>

#define PROMISC 1
#define NONPROMISC 0

void callback (u_char *useless, const struct pcap_pkthdr *pkthdr, const u_char *packet ); 

int main (int argc, char **argv)
{
	char *device = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *pcd;

	pcd = pcap_open_live(device, 2048, NONPROMISC, -1, errbuf);
	if (pcd==NULL){
		printf("%s\n", errbuf);
		return 1;
	}

	if (pcap_set_datalink(pcd, DLT_EN10MB)) 
	return 1;
	pcap_loop(pcd, -1, callback, NULL);
	return 0;
}

void callback (u_char *useless, const struct pcap_pkthdr *pkthdr, const u_char *packet ) {

	const struct libnet_ethernet_hdr * ether_packet = (const struct libnet_ethernet_hdr *)packet;
	uint8_t * d_mac = (uint8_t *)(ether_packet->ether_dhost);
	uint8_t * s_mac = (uint8_t *)(ether_packet->ether_shost);
	printf("------------------------------\n");
	printf("Destination MAC address : %02X:%02X:%02X:%02X:%02X:%02X\n", d_mac[0], d_mac[1], d_mac[2], d_mac[3], d_mac[4], d_mac[5]);
	printf("Source MAC address : %02X:%02X:%02X:%02X:%02X:%02X\n", s_mac[0], s_mac[1], s_mac[2], s_mac[3], s_mac[4], s_mac[5]);
	
	if ( ntohs(ether_packet->ether_type) == ETHERTYPE_IP )
	{
		const struct libnet_ipv4_hdr *ip_packet = (const struct libnet_ipv4_hdr*)(packet+14);
		int ip_header_len = ((*(packet+14))%16)*4;
		
		printf("Source IP address : %d.%d.%d.%d\n" , *(packet+26), *(packet+27), *(packet+28), *(packet+29));
		printf("Destination IP address : %d.%d.%d.%d\n" , *(packet+30), *(packet+31), *(packet+32), *(packet+33) );
		
		if ( *(packet+23) == IPPROTO_TCP )
		{
			const struct libnet_tcp_hdr *i_packet = (const struct libnet_tcp_hdr *)(packet+14+ip_header_len); 
			printf("Source port : %u\n Destination port: %u\n",(u_short)ntohs(i_packet->th_sport), (u_short)ntohs(i_packet->th_dport));
			printf("-----------------------------\n");
		}	
	}

}

