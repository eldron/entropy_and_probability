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
#include <math.h>

int adjacent_matrix[256][256];
double entropy;
char buffer[65536];
int payload_length;
char filename[100];
int adjacent_count[256][256];
int byte_frequency[256];

// 
int main(int argc, char ** args){
	if(argc != 4){
		printf("usage: ./process matrix_file packets_path payload_length\n");
		return 0;
	}

	int i;
	int j;
	FILE * matrix_file = fopen("r", args[1]);
	if(matrix_file){
		for(i = 0;i < 256;i++){
			for(j = 0;j < 256;j++){
				adjacent_matrix[i][j] = fgetc(matrix_file);
			}
		}
		fclose(matrix_file);
	} else {
		printf("can not open matrix file %s\n", args[1]);
		return 0;
	}
	payload_length = atoi(args[3]);

	DIR * dir = opendir(args[2]);
	if(dir){
		struct dirent * ent = NULL;
		pcap_t * pcap = NULL;
		char errbuf[PCAP_ERRBUF_SIZE];
		char * packet = NULL;
		struct pcap_pkthdr header;
		struct ether_header * eth_hdr = NULL;
		struct ip * ip_hdr = NULL;
		struct tcphdr * tcp_hdr = NULL;
		struct udphdr * udp_hdr = NULL;
		char * data = NULL;
		int data_len = 0;

		while((ent = readdir(dir)) != NULL){
			pcap = pcap_open_offline(ent->d_name, errbuf);
			if(pcap){
				int bytes_count = 0;

				while((packet = pcap_next(pcap, &header)) != NULL){
					if(header.caplen < sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr)){
						printf("packet too short");
					} else {
						eth_hdr = (struct ether_header *) packet;
						unsigned short ether_type = ntohs(eth_hdr->ether_type);
						if(ether_type == 0x0800){
							// ip packet
							ip_hdr = (struct ip *) (packet + sizeof(struct ether_header));
						} else if(ether_type == 0x8100){
							// vlan packet
							unsigned short * vlan_proto = (unsigned short *) (packet + sizeof(struct ether_header) + 2);
							if(ntohs(*vlan_proto) == 0x0800){
								ip_hdr = (struct ip *) (packet + sizeof(struct ether_header) + 4);
							} else {
								ip_hdr = NULL;
							}
						} else {
							ip_hdr = NULL;
						}

						if(ip_hdr){
							if(ip_hdr->ip_v == 4){
								data = NULL;
								data_len = 0;
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
								}

								if(data){
									int tocopy = 0;
									if(payload_length - bytes_count > data_len){
										tocopy = data_len;
									} else {
										tocopy = payload_length - bytes_count;
									}
									
									for(i = 0;i < tocopy;i++){
										buffer[bytes_count + i] = data[i];
									}
									bytes_count += tocopy;
									if(bytes_count == payload_length){
										break;
									}
								}
							}
						}
					}
				}

				if(bytes_count == payload_length){
					for(i = 0;i < 100;i++){
						filename[i] = '\0';
					}
					strcpy(filename, ent->d_name);
					strcat(filename, ".result");
					FILE * file = fopen(filename, "w");
					// calculate entropy and byte adjacent information, write the result to file
					for(i = 0;i < 256;i++){
						for(j = 0;j < 256;j++){
							adjacent_count[i][j] = 0;
						}
						byte_frequency[i] = 0;
					}

					for(i = 0;i < payload_length - 1;i++){
						if(adjacent_matrix[buffer[i]][buffer[i + 1]]){
							adjacent_count[buffer[i]][buffer[i + 1]]++;
						}
					}
					for(i = 0;i < 256;i++){
						for(j = 0;j < 256;j++){
							if(adjacent_matrix[i][j]){
								fprintf(file, "%f ", (double) adjacent_count[i][j] / payload_length);
							}
						}
					}

					for(i = 0;i < payload_length;i++){
						byte_frequency[buffer[i]]++;
					}
					entropy = 0;
					for(i = 0;i < 256;i++){
						entropy += ((double) byte_frequency[i] / payload_length) * (log2((double) byte_frequency[i] / payload_length));
					}
					entropy = 0 - entropy;
					fprintf(file, "%f\n", entropy);
					fclose(file);
				}
			} else {
				printf("can not open file %s\n", ent->d_name);
			}
		}
	} else {
		printf("can not open dir %s\n", args[2]);
		return 0;
	}
}
