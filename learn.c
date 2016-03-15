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

int main(int argc, char ** args){
	if(argc != 2){
		printf("usage: ./learn path_of_unencrypted_packets\n");
		return 0;
	}

	DIR * dir = opendir(args[1]);
	if(dir){
		struct dirent * ent = NULL;
		while((ent = readdir(dir) != NULL){
			printf("%s\n", ent->d_name);
		}

		return 0;
	} else {
		printf("can not open dir %s\n", args[1]);
		return 0;
	}
}
