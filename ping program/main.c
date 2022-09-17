#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <errno.h>
#include "fill_packet.h"
unsigned short csum(unsigned short*,int);
static struct ifreq req;
pid_t pid;

int main(int argc, char* argv[])
{
	int sockfd, sockfd1;
	if((sockfd = socket(AF_INET, SOCK_RAW , IPPROTO_ICMP)) < 0)
	{
		perror("socket");
		exit(1);
	}
	if((sockfd1 = socket(AF_INET, SOCK_RAW , IPPROTO_ICMP)) < 0)
	{
		perror("socket1");
		exit(1);
	}
	//struct ifreq req;
	memset(&req,0,sizeof(req));
	strcpy(req.ifr_ifrn.ifrn_name,argv[2]);
	if(ioctl(sockfd,SIOCGIFADDR,&req) < 0){
        perror("ioctl error");
        exit(1);
    }
	char *my_ip = inet_ntoa(((struct sockaddr_in *)&req.ifr_addr)->sin_addr);
	char my_ip1[20] = "";
	strcpy(my_ip1,my_ip);

	memset(&req,0,sizeof(req));
	strcpy(req.ifr_ifrn.ifrn_name,argv[2]);
	if(ioctl(sockfd,SIOCGIFNETMASK,&req) < 0){
        perror("ioctl error");
        exit(1);
    }
	char *mask = inet_ntoa(((struct sockaddr_in *)&req.ifr_addr)->sin_addr);
	//printf("%s %s\n",mask,my_ip1);
	int on = 1;
	pid = getpid();
	struct sockaddr_in dst;
	myicmp *packet = (myicmp*)malloc(PACKET_SIZE); 
	int count = DEFAULT_SEND_COUNT;
	int timeout = atoi(argv[4]);
	unsigned int i;
	unsigned int submask = inet_addr(mask);
	unsigned int net_addr = inet_addr(my_ip1) & submask;
	/* 
	 * in pcap.c, initialize the pcap
	 */
	
	//printf("%d %d\n",net_addr,submask);
	//printf("%u\n",htonl(~submask));
	u_char *packet1 = (u_char*) malloc(PACKET_SIZE);
	for(i = 1 ; i < htonl(~submask) ; i++){
		int i1 = htonl(i);
		unsigned int lan_addr = (net_addr & submask) | i1;
		struct in_addr addr;
		addr.s_addr = lan_addr;
		char *target = inet_ntoa(addr);
		if(!strcmp(target,my_ip1)) continue; 
		printf("PING %s (data size = 10, id = 0x%x, seq = %d, timeout = %d ms)\n",target,pid,i,timeout*1000);
		strcpy(packet -> data,"M103040054");
		// fill ip header
		packet -> ip_hdr.ip_hl = 5;
		packet -> ip_hdr.ip_id = 0; //
		packet -> ip_hdr.ip_len = sizeof(struct ip) + sizeof(struct icmphdr) + strlen(packet -> data);
		packet -> ip_hdr.ip_off = 0; //
		packet -> ip_hdr.ip_p = IPPROTO_ICMP;
		packet -> ip_hdr.ip_tos = 0;
		packet -> ip_hdr.ip_ttl = 1;
		packet -> ip_hdr.ip_v = 4;
		packet -> ip_hdr.ip_src.s_addr = inet_addr(my_ip1);
		packet -> ip_hdr.ip_dst.s_addr = inet_addr(target);
		// fill icmp header
		packet -> icmp_hdr.type = 8;
		packet -> icmp_hdr.code = 0;
		packet -> icmp_hdr.un.echo.id = htons(pid);
		packet -> icmp_hdr.un.echo.sequence = htons(i);
		packet -> icmp_hdr.checksum = 0;
		packet -> icmp_hdr.checksum = csum((unsigned short*) &packet -> icmp_hdr,18);

		struct timeval sock_timeout;      
  		sock_timeout.tv_sec = timeout;
  		sock_timeout.tv_usec = 0;
		if (setsockopt (sockfd1, SOL_SOCKET, SO_RCVTIMEO, (char *)&sock_timeout,sizeof(sock_timeout)) < 0)
      	{	
			perror("setsockopt failed\n");
			exit(1);
		}
		if(setsockopt( sockfd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0)
		{
			perror("setsockopt");
			exit(1);
		}
		dst.sin_family = AF_INET;
		//printf("%d %d\n",packet -> ip_hdr.ip_sum,packet -> icmp_hdr.checksum);
		/*
		*   Use "sendto" to send packets, and use "pcap_get_reply"(in pcap.c) 
			or use the standard socket like the one in the ARP homework
		*   to get the "ICMP echo response" packets 
		*	 You should reset the timer every time before you send a packet.
		*/
		struct timeval send_t, recv_t;
		gettimeofday(&send_t,NULL);
		if(sendto(sockfd, (void*)packet, packet -> ip_hdr.ip_len, 0, (struct sockaddr *)&dst, sizeof(dst)) < 0)
		{
				perror("sendto");
				exit(1);
		}
		memset(packet,0,sizeof(packet));
		
		socklen_t len = sizeof(dst);
		if(recvfrom(sockfd1,packet1,PACKET_SIZE,0,(struct sockaddr*) &dst,&len) < 0){
			printf("timeout\n");
			continue;
		}
		gettimeofday(&recv_t,NULL);
		double total = (recv_t.tv_sec * 1000000 + recv_t.tv_usec) - (send_t.tv_sec * 1000000 + send_t.tv_usec);
		struct ip *ip1 = (struct ip*) packet1;
		unsigned int iphdr_len =  (ip1 -> ip_hl) << 2;
		struct icmphdr *icmp1 = (struct icmphdr*) (packet1 + iphdr_len);
		if(icmp1 -> type == 0 && htons(icmp1 -> un.echo.id) == pid && htons(icmp1 ->un.echo.sequence) == i){
			printf("Reply from : %s, time : %lf ms\n",inet_ntoa(ip1->ip_src),total/1000);
		} 
		if(icmp1 -> type == 11){
			printf("Destination unreachable\n");
		}
		memset(packet1,0,PACKET_SIZE);
	}
	free(packet);
	free(packet1);
	return 0;
}

unsigned short csum(unsigned short *addr,int len) 
{
	int nleft = len;
        uint32_t sum = 0;
        uint16_t *w = addr;
        uint16_t answer = 0;

        while (nleft > 1) {
                sum += *w++;
                nleft -= 2;
        }

        if (nleft == 1) {
                *(unsigned char *) (&answer) = *(unsigned char *) w;
                sum += answer;
        }

        sum = (sum >> 16) + (sum & 0xffff);
        sum += (sum >> 16);
        answer = ~sum;
        return answer;
}