#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pcap.h>

#define SWAP_SHORT(x) (((x & 0x00ff) << 8) | ((x & 0xff00) >> 8))

int packets_count = 0;
int vlan_packets_count = 0;
int tcp_packets_count = 0;
int udp_packets_count = 0;
int adjacent_count[0xff][0xff];
int adjacent_matrix[0xff][0xff];

void init(){
	packets_count = 0;
	vlan_packets_count = 0;
	tcp_packets_count = 0;
	udp_packets_count = 0;
	int i;
	int j;
	for(i = 0;i < 0xff;i++){
		for(j = 0;j < 0xff;j++){
			adjacent_matrix[i][j] = adjacent_count[i][j] = 0;
		}
	}
}

void write_adjacent_matrix(char * filename){
	FILE * file = fopen("w", filename);
	if(file){
		int i;
		int j;
		for(i = 0;i < 0xff;i++){
			for(j = 0;j < 0xff;j++){
				fprintf(file, "%d", adjacent_matrix[i][j]);
			}
		}
		fclose(file);
	} else {
		printf("can not open file %s\n", filename);
	}
}

void process_ip_packet(struct ip * ip_hdr){

}

int main(int argc, char ** args){
	if(argc != 3){
		printf("usage: ./learn path_of_unencrypted_packets result_file\n");
		return 0;
	}

	init();

	DIR * dir = opendir(args[1]);
	if(dir){
		struct dirent * ent = NULL;
		pcap_t * pcap = NULL;
		char errbuf[PCAP_ERRBUF_SIZE];
		const unsigned char * packet = NULL;
		struct pcap_pkthdr header;
		struct ether_header * eth_hdr = NULL;
		struct ip * ip_hdr = NULL;
		struct tcphdr * tcp_hdr = NULL;
		struct udphdr * udp_hdr = NULL;

		while((ent = readdir(dir)) != NULL){
			printf("%d: %s\n", ent->d_type, ent->d_name);
			if(ent->d_type == DT_REG){
				pcap = pcap_open_offline(ent->d_name, errbuf);
				if(pcap){
					while((packet = pcap_next(pcap, &header)) != NULL){
						// count adjacent byte frequencies
						if(header.caplen < sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr)){
							printf("packet too short\n");
						} else {
							eth_hdr = (struct ether_header *) packet;
							unsigned short ether_type = SWAP_SHORT(eth_hdr->ether_type);
							if(ether_type == 0x0800){
								// ip packet
								ip_hdr = (struct ip *) (packet + sizeof(ether_header));
								process_ip_packet(ip_hdr);
							} else if(ether_type == 0x8100){
								// vlan packet
								
							} else {

							}
						}
					}
				} else {
					printf("error reading pcap file %s\n", errbuf);
				}
			}
		}

		return 0;
	} else {
		printf("can not open dir %s\n", args[1]);
		return 0;
	}
}
