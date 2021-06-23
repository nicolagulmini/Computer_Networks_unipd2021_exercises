/*
	implement an arp cache
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

unsigned char my_mac[6] = // 
unsigned char my_ip[4] = // 
unsigned char broadcast_mac[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
unsigned char mask[4] = {255, 255, 255, 0};
unsigned char gateway[4] = // 

struct arp_entry
{
	unsigned char target_ip[4];
	unsigned char target_mac[6];
};

int s; // socket
int i, j, k, n, len, t;
struct sockaddr_ll sll;


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
	unsigned char destination_address[4]; // it can be also unsigned int
	// unsigned char options[3]; // we can play with these options, but they are not so used so for now let ignore them
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
	// a cast is needed
	char * a = (char *) a1;
	char * b = (char *) a2;

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
	unsigned char buffer[1500];
	struct arp_packet * arp;
	struct ethernet_frame * eth;
	eth = (struct ethernet_frame *) buffer;
	arp = (struct arp_packet *) eth->payload;
	arp->hardware_address = htons(1); 
	arp->protocol_address = htons(0x0800);
	arp->hardware_len = 6; 
	arp->protocol_len = 4;
	arp->arp_operation = htons(1);
	
	for(i=0; i<4; i++) arp->sender_ip_address[i] = my_ip[i];
	for(i=0; i<6; i++) arp->sender_mac_address[i] = my_mac[i];
	for(i=0; i<6; i++) arp->target_mac[i] = 0; 
	for(i=0; i<4; i++) arp->target_ip[i] = ip[i];

	for(i=0; i<6; i++) eth->destination_mac_address[i] = broadcast_mac[i];
	for(i=0; i<6; i++) eth->source_mac_address[i] = my_mac[i];
	eth->upper_layer_protocol = htons(0x0806);
	
	printbuf(buffer, 14+sizeof(struct arp_packet));
	
	len = sizeof(struct sockaddr_ll);
	bzero(&sll, len);
	sll.sll_family = AF_PACKET;
	sll.sll_ifindex = if_nametoindex("eth0");	

	n = sendto(s, buffer, 14+sizeof(struct arp_packet), 0, (struct sockaddr *) &sll, len);
	if (n == -1) { perror("Sendto failed. Return."); return -1; }
	
	for (k=0; k<100; k++)
	{
		n = recvfrom(s, buffer, 1500, 0, (struct sockaddr *) &sll, &len);
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

int table_check(struct arp_entry* table, unsigned char* ip, int table_size, unsigned char* target_mac)
{
	int i;
	for (i = 0; i < table_size; i++)
	{
		if (are_equal((&table[i])->target_ip, ip, 4)) // if there is the ip address, then there is also the already resolved mac!
		{
			for (j = 0; j < 6; j++) target_mac[j] = (&table[i])->target_mac[j];
			return 1;
		}
	}
	return 0;
}

void insert_entry(struct arp_entry* table, int* size, unsigned char* ip, unsigned char* mac)
{
	int i;
	for (i = 0; i < 4; i++) (&table[*size])->target_ip[i] = ip[i];
	for (i = 0; i < 6; i++) (&table[*size])->target_mac[i] = mac[i];
	*size = *size + 1;
}

int main(int argc, char** argv)
{
	s = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (s == -1) { perror("Socket failed. Return."); return -1; }

	len = sizeof(struct sockaddr_ll);
	bzero(&sll, len); 
	sll.sll_family = AF_PACKET;
	sll.sll_ifindex = if_nametoindex("eth0");

	// define the table as an array of arp entries
	struct arp_entry table[1];
	int arp_table_size = 0;

	unsigned char target_ip[4] = { 88, 80, 187, 10 };
	unsigned char target_mac[6] = { 0xF2, 0x3C, 0x91, 0x56, 0xE5, 0x89 }; // already resolved
	// put in advance to test if the table_check works
	insert_entry(table, &arp_table_size, target_ip, target_mac);
	
	// redefine target_mac 
	int i;
	for (i = 0; i < 6; i++)
		target_mac[i] = 0;

	printf("Target address: %d.%d.%d.%d \n", target_ip[0], target_ip[1], target_ip[2], target_ip[3]);
	//printf("Arp table size: %d\n", arp_table_size);

	if (table_check(table, target_ip, arp_table_size, target_mac) == 0) // if table_check returns 1, target_mac is already resolved
	{
		// the target is in my own network?
		if (((*(unsigned int*)target_ip) & (*(unsigned int*)mask)) == ((*(unsigned int*)my_ip) & (*(unsigned int*)mask)))
			t = resolve_mac(target_ip, target_mac);
		else t = resolve_mac(gateway, target_mac);

		if (t == -1) { perror("Resolve mac failed. Return."); return -1; }

		printf("Resolved mac: ");
		printbuf(target_mac, 6);
		printf("\n");

		// add the entry in the table
		for (i = 0; i < 4; i++) (&table[arp_table_size])->target_ip[i] = target_ip[i];
		for (i = 0; i < 6; i++) (&table[arp_table_size])->target_mac[i] = target_mac[i];
		arp_table_size++;
	}

	else
	{
		printf("Found mac in the table: ");
		printbuf(target_mac, 6);
		printf("\n");
	}

	printf("Print the arp table at the end of the program:\n");
	for (i = 0; i < arp_table_size; i++)
	{
		printf("Entry number %d:\n", i+1);
		printf("IP: ");
		printbuf((&table[i])->target_ip, 4);
		printf("related MAC: ");
		printbuf((&table[i])->target_mac, 6);
		printf("\n");
	}
	return 0;
}
