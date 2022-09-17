#include "arp.h"

#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <linux/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

//You can fill the following functions or add other functions if needed. If not, you needn't write anything in them.  
void set_hard_type(struct ether_arp *packet, unsigned short int type)
{}
void set_prot_type(struct ether_arp *packet, unsigned short int type)
{}
void set_hard_size(struct ether_arp *packet, unsigned char size)
{}
void set_prot_size(struct ether_arp *packet, unsigned char size)
{}
void set_op_code(struct ether_arp *packet, short int code)
{}

void set_sender_hardware_addr(struct ether_arp *packet, char *address)
{}
void set_sender_protocol_addr(struct ether_arp *packet, char *address)
{}
void set_target_hardware_addr(struct ether_arp *packet, char *address)
{}
void set_target_protocol_addr(struct ether_arp *packet, char *address)
{}

unsigned char* get_target_protocol_addr(struct ether_arp *packet)
{
	return packet -> arp_tpa;
}
unsigned char* get_sender_protocol_addr(struct ether_arp *packet)
{
	return packet -> arp_spa;
}
char* get_sender_hardware_addr(struct ether_arp *packet)
{
	return packet -> arp_sha;
}
char* get_target_hardware_addr(struct ether_arp *packet)
{
	return packet -> arp_tha;
}
int is_address_equal(unsigned char* target,unsigned char* filter)
{
	int i = 0;
	for(; i < 4 ; i++){
		if(target[i] != filter[i]) return 0;
	}
	return 1;
}