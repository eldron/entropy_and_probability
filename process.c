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

int vector_length = 0;
int adjacent_matrix[256][256];
double vector[65536];
double entropy;

void process_ip_packet(struct ip * ip_hdr, FILE * file){
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
			int bit_array[10000];
			int i;
			for(i = 0;i < 10000;i++){
				bit_array[i] = 0;
			}

			for(i = 0;i < data_len - 1;i++){
				bit_array[i] = adjacent_matrix[data[i]][data[i + 1]];
			}

			int continuous[10000];
			int count = 0;
			int idx = 0;
			for(i = 0;i < data_len - 1;i++){
				if(bit_array[i] == 1){
					count++;
				} else {
					if(count){
						continuous[idx] = count;
						count = 0;
						idx++;
					}
				}
			}
			// sort continuous in descending order
			int j;
			int max = 0;
			int maxidx = 0;
			for(i = 0;i < idx - 1;i++){
				for(j = i;j < idx;j++){
					if(max < continuous[j]){
						max = continuous[j];
						maxidx = j;
					}
				}

				int value = continuous[i];
				continuous[i] = continuous[maxidx];
				continuous[maxidx] = value;
			}

			for(i = 0;i < vector_length;i++){
				fprintf(file, "%f ", (double) (continuous[i] / data_len));
			}

			// calculate entropy, write to file
			double entropy = 0;
			int times[256];
			for(i = 0;i < 256;i++){
				times[i] = 0;
			}
			for(i = 0;i < data_len;i++){
				times[data[i]]++;
			}
			for(i = 0;i < 256;i++){
				entropy += ((double) times[i] / data_len) * log2((double) times[i] / data_len);
			}
			entropy = 0 - entropy;
			fprintf(file, "%f\n", entropy);
		}
	} else {
		printf("not ipv4 packet\n");
	}
}

int main(int argc, char ** args){
	if(argc != 5){
		printf("usage: ./process vector_length matrix_file packets_path result_file\n");
		return 0;
	}

	vector_length = atoi(args[1]);
	FILE * file = fopen("r", args[2]);
	if(file){
		int i;
		int j;
		for(i = 0;i < 256;i++){
			for(j = 0;j < 256;j++){
				adjacent_matrix[i][j] = fgetc(file);
			}
		}
	} else {
		printf("cano not open file %s\n", args[2]);
		return 0;
	}

	DIR * dir = opendir(args[3]);
	if(dir){
		struct dirent * ent = NULL;
		pcap_t * pcap = NULL;
		char errbuf[PCAP_ERRBUF_SIZE];
		const unsigned char * packet = NULL;
		struct pcap_pkthdr header;
		struct ether_header * eth_hdr = NULL;
		struct ip * ip_hdr = NULL;

		while((ent = readdir(dir)) != NULL){
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
				printf("can not open file %s\n", ent->d_name);
			}
		}
	} else {
		printf("can not open dir %s\n", args[3]);
		return 0;
	}
}