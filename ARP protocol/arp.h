#ifndef __ARP_UTIL_H__
#define __ARP_UTIL_H__

#include <netinet/if_ether.h>

struct arp_packet
{
	struct ether_header eth_hdr;
	struct ether_arp arp;
};
struct arp_header{
	unsigned short h_format;
	unsigned short p_format;
	unsigned char hlen;
	unsigned char plen;
	unsigned short op;
	unsigned char source_mac[6];
	unsigned char source_ip[4];
	unsigned char target_mac[6];
	unsigned char target_ip[4];
};
void print_usage();


void set_hard_type(struct ether_arp *packet, unsigned short int type);
void set_prot_type(struct ether_arp *packet, unsigned short int type);
void set_hard_size(struct ether_arp *packet, unsigned char size);
void set_prot_size(struct ether_arp *packet, unsigned char size);
void set_op_code(struct ether_arp *packet, short int code);

void set_sender_hardware_addr(struct ether_arp *packet, char *address);
void set_sender_protocol_addr(struct ether_arp *packet, char *address);
void set_target_hardware_addr(struct ether_arp *packet, char *address);
void set_target_protocol_addr(struct ether_arp *packet, char *address);

unsigned char* get_target_protocol_addr(struct ether_arp *packet); 
unsigned char* get_sender_protocol_addr(struct ether_arp *packet); 
char* get_sender_hardware_addr(struct ether_arp *packet); 
char* get_target_hardware_addr(struct ether_arp *packet); 
int is_address_equal(unsigned char*,unsigned char*);
#endif
