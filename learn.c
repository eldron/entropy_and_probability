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
int adjacent_count[256][256];
int adjacent_matrix[256][256];

void init(){
	packets_count = 0;
	vlan_packets_count = 0;
	tcp_packets_count = 0;
	udp_packets_count = 0;
	int i;
	int j;
	for(i = 0;i < 256;i++){
		for(j = 0;j < 256;j++){
			adjacent_matrix[i][j] = adjacent_count[i][j] = 0;
		}
	}
}

void write_adjacent_matrix(char * filename){
	FILE * file = fopen("w", filename);
	if(file){
		int i;
		int j;
		for(i = 0;i < 256;i++){
			for(j = 0;j < 256;j++){
				fprintf(file, "%d", adjacent_matrix[i][j]);
			}
		}
		fclose(file);
	} else {
		printf("can not open file %s\n", filename);
	}
}

void process_ip_packet(struct ip * ip_hdr){
	struct tcphdr * tcp_hdr = NULL;
	struct udphdr * udp_hdr = NULL;
	if(ip_hdr->ip_v == 4){
		char * data = NULL;
		int data_len = 0;

		if(ip_hdr->ip_p == 6){
			 char * tmp = (char *) ip_hdr;
			 tcp_hdr = (struct tcphdr *) (tmp + ip_hdr->ip_hl * 4);
			 data_len = ip_hdr->ip_len - ip_hdr->ip_hl * 4 - tcp_hdr->th_off * 4;
			 if(data_len > 0){
			 	data = tmp + ip_hdr->ip_hl * 4 + tcp_hdr->th_off * 4;
			 }
		} else if(ip_hdr->ip_p == 17){
			char * tmp = (char *) ip_hdr;
			data_len = ip_hdr->ip_len - ip_hdr->ip_hl * 4 - sizeof(struct udphdr);
			if(data_len > 0){
				data = tmp + ip_hdr->ip_hl * 4 + sizeof(struct udphdr);
			}
		} else {
			printf("not tcp or udp packet\n");
		}

		if(data){
			int i;
			for(i = 0;i < data_len - 1;i++){
				adjacent_count[data[i]][data[i + 1]]++;
			}
		}
	} else {
		printf("not ipv4 packet\n");
	}
}

void cal_adjacent_matrix(){
	int tmp[256 * 256];
	int i;
	int j;
	int k = 0;
	for(i = 0;i < 256;i++){
		for(j = 0;j < 256;j++){
			tmp[k] = adjacent_count[i][j];
			k++;
		}
	}

	// sort tmp, descending order
	for(i = 0;i < 65536 - 1;i++){
		int max = 0;
		int idx = i + 1;
		for(j = i + 1;j < 65536;j++){
			if(tmp[j] > max){
				max = tmp[j];
				idx = j;
			}
		}

		int value = tmp[i];
		tmp[i] = tmp[idx];
		tmp[idx] = value;
	}

	int special_line = 65536 / 5;
	int special_value = tmp[special_line];
	for(i = 0;i < 256;i++){
		for(j = 0;j < 256;j++){
			if(adjacent_count[i][j] >= special_value){
				adjacent_matrix[i][j] = 1;
			} else {
				adjacent_matrix[i][j] = 0;
			}
		}
	}
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
								ip_hdr = (struct ip *) (packet + sizeof(struct ether_header));
								process_ip_packet(ip_hdr);
							} else if(ether_type == 0x8100){
								// vlan packet
								unsigned short * vlan_proto = (unsigned short *) (packet + sizeof(struct ether_header) + 2);
								if(*vlan_proto == 0x0800){
									vlan_packets_count++;
									ip_hdr = (struct ip *) (packet + sizeof(struct ether_header) + 4);
									process_ip_packet(ip_hdr);
								}
							} else {

							}
						}
					}
				} else {
					printf("error reading pcap file %s\n", errbuf);
				}
			}
		}

		cal_adjacent_matrix();
		write_adjacent_matrix(args[2]);
		return 0;
	} else {
		printf("can not open dir %s\n", args[1]);
		return 0;
	}
}
