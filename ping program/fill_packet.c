#include "fill_packet.h"
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/types.h>


void 
fill_iphdr ( struct ip *ip_hdr , const char* dst_ip)
{
	
}

void
fill_icmphdr (struct icmphdr *icmp_hdr)
{
	
}

u16
fill_cksum(struct icmphdr* icmp_hdr)
{
	
}