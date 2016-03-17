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
				
			} else {
				printf("can not open file %s\n", ent->d_name);
			}
		}
	} else {
		printf("can not open dir %s\n", args[3]);
		return 0;
	}
}