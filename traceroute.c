/*
	Build a traceroute:	send an echo request message
	starting from time_to_live = 1 and increasing it.
	Wait for the reply and detect who has sent it.
	If the time_to_live becomes 0 before reaching the destination (the target ip) 
	the node at which this happened hopefully sends a Time Exceeded reply. 
	NOTE that since icmp is used for diagnostics, this reply serive is not mandatory 
	and the node may not reply. 
	For this reason, in this version of the exercise, the chosen target ip is 8.8.8.8, that replies for sure!
*/

#include <stdio.h>
#include <net/if.h>
#include <arpa/inet.h> 
#include <stdlib.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>

#define MAX_LEN_BUFFER 3000

unsigned char my_mac[6] = //
unsigned char my_ip[4] = //
unsigned char broadcast_mac[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
unsigned char mask[4] = { 255, 255, 255, 0 };
unsigned char gateway[4] = //

int s; 
struct sockaddr_ll sll;

struct icmp_packet
{
	unsigned char type;
	unsigned char code;
	unsigned short int checksum;
	unsigned short int identifier;
	unsigned short int sequence_number;
	unsigned char payload[1];
};

struct ip_datagram
{
	unsigned char version_ihl;
	unsigned char type_of_service;
	unsigned short int total_length;
	unsigned short int identification;
	unsigned short int flags_offset;
	unsigned char time_to_live;
	unsigned char protocol;
	unsigned short int header_checksum;
	unsigned char source_address[4];
	unsigned char destination_address[4];
	unsigned char payload[1];  
};

struct ethernet_frame
{
	unsigned char destination_mac_address[6];
	unsigned char source_mac_address[6];
	unsigned short int upper_layer_protocol;
	unsigned char payload[1]; 
};

struct arp_packet
{
	unsigned short int hardware_address;
	unsigned short int protocol_address;
	unsigned char hardware_len;
	unsigned char protocol_len;
	unsigned short int arp_operation;
	unsigned char sender_mac_address[6];
	unsigned char sender_ip_address[4];
	unsigned char target_mac[6];
	unsigned char target_ip[4];
};

int are_equal(void * a1, void * a2, int size)
{
	char * a = (char *) a1;
	char * b = (char *) a2;

	int i;
	for (i=0; i<size; i++)
		if (a[i] != b[i])
			return 0;
	return 1; // True
}

void printbuf(unsigned char* buffer, int size)
{
	int i;
	for(i=0; i<size; i++)
		printf("%.2X(%.3d) ", buffer[i], buffer[i]);
	printf("\n");
}

int resolve_mac(unsigned char * ip, unsigned char * mac)
{
	unsigned char buffer[MAX_LEN_BUFFER];
	struct arp_packet * arp;
	struct ethernet_frame * eth;
	eth = (struct ethernet_frame *) buffer;
	arp = (struct arp_packet *) eth->payload;
	arp->hardware_address = htons(1); 
	arp->protocol_address = htons(0x0800);
	arp->hardware_len = 6;
	arp->protocol_len = 4;
	arp->arp_operation = htons(1);
	
	int i;
	for(i=0; i<4; i++) arp->sender_ip_address[i] = my_ip[i];
	for(i=0; i<6; i++) arp->sender_mac_address[i] = my_mac[i];
	for(i=0; i<6; i++) arp->target_mac[i] = 0; 
	for(i=0; i<4; i++) arp->target_ip[i] = ip[i]; 

	for(i=0; i<6; i++) eth->destination_mac_address[i] = broadcast_mac[i];
	for(i=0; i<6; i++) eth->source_mac_address[i] = my_mac[i];
	eth->upper_layer_protocol = htons(0x0806); 
	
	printbuf(buffer, 14+sizeof(struct arp_packet));
	
	int n; 
	int len = sizeof(struct sockaddr_ll);
	bzero(&sll, len);
	sll.sll_family = AF_PACKET;
	sll.sll_ifindex = if_nametoindex("eth0");	

	n = sendto(s, buffer, 14+sizeof(struct arp_packet), 0, (struct sockaddr *) &sll, len);
	if (n == -1) { perror("Sendto failed. Return."); return -1; }
	
	int k;
	for (k=0; k<100; k++) // a "while" loop
	{
		n = recvfrom(s, buffer, MAX_LEN_BUFFER, 0, (struct sockaddr *) &sll, &len);
		if (ntohs(eth->upper_layer_protocol) == 0x0806)
		{
			if (are_equal(ip, arp->sender_ip_address, 4))
			{
				for (i=0; i<6; i++) mac[i] = arp->sender_mac_address[i]; 
				return 0;
			}
		}	
	}
	return -1;
}

unsigned short int checksum(unsigned char * ip, int header_length)
{
	int i;
	unsigned short int * p = (unsigned short int *) ip;
	unsigned short int total = 0;
	unsigned short int prev = 0;
	for (i=0; i<header_length/2; i++)
	{
		total += ntohs(p[i]);
		if (total < prev) total++;
		prev = total;
	}
	if (i*2 != header_length) 
	{
		total += ip[header_length-1]<<8;
		if (total < prev) total++; 
	}
	return (0xffff - total);
}

void forge_icmp_echo(struct icmp_packet * icmp, int size_of_payload )
{
	icmp->type = 8;
	icmp->code = 0;
	icmp->checksum = htons(0);
	icmp->identifier = htons(0x1234); 
	icmp->sequence_number = htons(1);
	
	int i;
	for (i=0; i< size_of_payload; i++) icmp->payload[i] = i & 0xff; 
	
	icmp->checksum = htons(checksum((unsigned char *) icmp, 8+size_of_payload)); 
}

void forge_ip(struct ip_datagram * ip, int payloadsize, char proto, unsigned int target_ip, int timetolive)
{
	ip->version_ihl = 0x45; 
	ip->type_of_service = 0; 
	ip->total_length = htons(20 + payloadsize); 
	ip->identification = htons(0xabcd); // arbitrary
	ip->flags_offset = htons(0x4000);
	ip->time_to_live = timetolive;
	ip->protocol = proto; 
	ip->header_checksum = htons(0); 
	
	int i;
	unsigned char * target_ip_address;
	target_ip_address = (unsigned char *) &target_ip;
	for (i=0; i<4; i++) ip->source_address[i] = my_ip[i];
	for (i=0; i<4; i++) ip->destination_address[i] = target_ip_address[i];

	ip->header_checksum = htons(checksum((unsigned char *) ip, 20));
}

void forge_eth(struct ethernet_frame * eth, unsigned char * dest, unsigned short int ulp)
{
	int i;
	for (i=0; i<6; i++) eth->destination_mac_address[i] = dest[i];
	for (i=0; i<6; i++) eth->source_mac_address[i] = my_mac[i]; 
	eth->upper_layer_protocol = htons(ulp);
}

int main(int argc, char** argv)
{
	int n, t, len, k;
	s = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (s == -1) { perror("Socket failed. Return."); return -1; }
	
	len = sizeof(struct sockaddr_ll);
	bzero(&sll, len); 
	sll.sll_family = AF_PACKET;
	sll.sll_ifindex = if_nametoindex("eth0");
	
	unsigned char buffer[MAX_LEN_BUFFER];
	
	unsigned char target_ip[4] = { 8, 8, 8, 8}; // the IP address that replies for sure
	unsigned char target_mac[6];
	
	printf("Target address: %d.%d.%d.%d \n", target_ip[0], target_ip[1], target_ip[2], target_ip[3]);
	
	if (((*(unsigned int*)target_ip) & (*(unsigned int*)mask)) == ((*(unsigned int*)my_ip) & (*(unsigned int*)mask))) t = resolve_mac(target_ip, target_mac);
	else t = resolve_mac(gateway, target_mac);
	if (t == -1) { perror("Resolve mac failed. Return."); return -1; }
	
	printf("Resolved mac: ");
	printbuf(target_mac, 6);
	printf("\n");

	struct ethernet_frame * eth;
	struct ip_datagram * ip;
	struct icmp_packet * icmp;
	
	eth = (struct ethernet_frame *) buffer;	
	ip = (struct ip_datagram *) eth->payload;
	icmp = (struct icmp_packet *) ip->payload;
	
	int icmp_payload_size = 20; 
	 
	// the main part of the exercise
	int timetolive;
	int while_condition;
	for (timetolive = 1; timetolive <= 128; timetolive++)
	{
		while_condition = 1;
		printf("*** Time to live = %d ***\n", timetolive);
		forge_icmp_echo(icmp, icmp_payload_size);
		forge_ip(ip, 8 + icmp_payload_size, 1, *(unsigned int*)target_ip, timetolive);
		forge_eth(eth, target_mac, 0x0800);

		t = sendto(s, buffer, 42 + icmp_payload_size, 0, (struct sockaddr*)&sll, len);
		if (t == -1) { perror("Sendto (IP) failed. Return."); return -1; }

		printf("Listen...\n");
		while (while_condition)
		{
			n = recvfrom(s, buffer, 1500, 0, (struct sockaddr*)&sll, &len);
			if (ntohs(eth->upper_layer_protocol) == 0x0800)
				if (ip->protocol == 1 && icmp->code == 0)
				{
					printf("Just received a packet from %d.%d.%d.%d with icmp->type = %d\n", ip->source_address[0], ip->source_address[1], ip->source_address[2], ip->source_address[3], icmp->type);

					if (icmp->type == 3) printf("Destination Unreachable.\n\n"); // 
					if (icmp->type == 11) printf("Time Exceeded.\n\n");

					if (icmp->type == 0 && are_equal(ip->source_address, target_ip, 4))
					{	
						printf("Echo Reply.\n");
						printf("Minimum time to live to reach the desired destination = %d.\n", timetolive);
						printf("Note: ONLY in this case the icmp sequence number is %d and the icmp identifier is (hex) %x. In previous cases they were both 0.\n", ntohs(icmp->sequence_number), ntohs(icmp->identifier));
						return 0;
					}
					while_condition = 0;
				}
		}
	}
}
