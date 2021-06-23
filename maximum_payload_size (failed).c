/*
	Modify the ip.c program in order to check the fragmentation and the MTU
	without setting the Don't Fragment bit = 1
	and without checking the type = 3 and code = 4
	in the forward trip.
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

unsigned char my_mac[6] = { 0xf2, 0x3c, 0x91, 0xdb, 0xc2, 0x98};
unsigned char my_ip[4] = { 88, 80, 187, 84};
unsigned char broadcast_mac[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
unsigned char mask[4] = {255, 255, 255, 0};
unsigned char gateway[4] = {88, 80, 187, 1};

int s; // socket
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
	arp->hardware_len = 6; // no htons because it is one byte
	arp->protocol_len = 4;
	arp->arp_operation = htons(1);
	
	int i;
	for(i=0; i<4; i++) arp->sender_ip_address[i] = my_ip[i];
	for(i=0; i<6; i++) arp->sender_mac_address[i] = my_mac[i];
	for(i=0; i<6; i++) arp->target_mac[i] = 0; // will be filled
	for(i=0; i<4; i++) arp->target_ip[i] = ip[i]; // ip passed as parameter

	for(i=0; i<6; i++) eth->destination_mac_address[i] = broadcast_mac[i];
	for(i=0; i<6; i++) eth->source_mac_address[i] = my_mac[i];
	eth->upper_layer_protocol = htons(0x0806); // arp request
	
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
		// in sendto we put 'len' but in recvfrom we put '&len' because in that case it can be modified.
		if (ntohs(eth->upper_layer_protocol) == 0x0806)
		{
			if (are_equal(ip, arp->sender_ip_address, 4))
			{
				for (i=0; i<6; i++) mac[i] = arp->sender_mac_address[i]; 
				// because now the sender is the host that sends the arp response to us!
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
		total += ntohs(p[i]); // htons or ntohs is the same thing. We only have to swap
		// to check the carry we can use 32 bits length, but let's suppose that we do not have such words
		if (total < prev) total++;
		prev = total;
		// a smart way to check the carry and perform one's complement sum	
	}
	if (i*2 != header_length) 
	{
		total += ip[header_length-1]<<8; // because ip[header_length-1] is a byte, while total is a short int
		// we can also do total += htons(p[header_length/2] & 0xff00);
		if (total < prev) total++; 
	}
	// we have to return the one's complement of the result, it can be done using the tilde operator
	// otherwise we can do so
	return (0xffff - total);
	// we are just returning a value, so we DO NOT CHANGE THE ENDIANESS! 
	// we do not return htons((0xffff-total));
	// because this is only a method, not a packet writer
	// but remember to change the endianness on the returned value once called this method
}

void forge_icmp_echo(struct icmp_packet * icmp, int size_of_payload )
{
	icmp->type = 8;
	icmp->code = 0;
	icmp->checksum = htons(0);
	icmp->identifier = htons(0x1234); // arbitrary pattern that can be recognise easily
	icmp->sequence_number = htons(1);
	
	int i;
	for (i=0; i< size_of_payload; i++) icmp->payload[i] = i & 0xff; // a typical pattern. The and is done to not exceed the size
	
	icmp->checksum = htons(checksum((unsigned char *) icmp, 8+size_of_payload)); // 8 + size_of_payload	
}

void forge_ip(struct ip_datagram * ip, int payloadsize, char proto, unsigned int target_ip, int timetolive)
{
	ip->version_ihl = 0x45; // no htons 
	ip->type_of_service = 0; // useless 
	ip->total_length = htons(20 + payloadsize); // 20 for the header and payloadsize is the size passed as a parameter, because we don't know
	ip->identification = htons(0xabcd); // arbitrary
	ip->flags_offset = htons(0x4000);
	ip->time_to_live = timetolive;
	ip->protocol = proto; 
	ip->header_checksum = htons(0); // "before computing the checksum" - rfc
	
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
	// otherwise we can do: memcpy(eth->destination_mac_address, dest, 4); that is the same but in only one line!
	// on man memcpy we can see that memcpy(dest, src, size) performs in that way
	// se also have to include <string.h> that is different from <strings.h>
	for (i=0; i<6; i++) eth->source_mac_address[i] = my_mac[i]; 
	eth->upper_layer_protocol = htons(ulp);
}

int main(int argc, char** argv)
{
	int n, t, len, k;
	s = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL)); // packet socket
	if (s == -1) { perror("Socket failed. Return."); return -1; }
	
	// struct sockaddr_ll sll already defined 
	len = sizeof(struct sockaddr_ll);
	bzero(&sll, len); 
	sll.sll_family = AF_PACKET;
	sll.sll_ifindex = if_nametoindex("eth0");
	
	unsigned char buffer[MAX_LEN_BUFFER];
	
	// resolve mac and print
	unsigned char target_ip[4] = { 99, 77, 148, 0 }; //{88, 80, 187, 10}; // 
	unsigned char target_mac[6];
	
	printf("Target address: %d.%d.%d.%d \n", target_ip[0], target_ip[1], target_ip[2], target_ip[3]);
	
	// the target is in my own network?
	if (((*(unsigned int*)target_ip) & (*(unsigned int*)mask)) == ((*(unsigned int*)my_ip) & (*(unsigned int*)mask)))
	{
		t = resolve_mac(target_ip, target_mac);
		printf("Target in my LAN.\n");
	}
	
	else
	{
		t = resolve_mac(gateway, target_mac);
		printf("Target is external.\n");
	}
		
	if (t == -1) { perror("Resolve mac failed. Return."); return -1; }
	
	printf("Resolved mac: ");
	printbuf(target_mac, 6);
	printf("\n");

	// packets
	struct ethernet_frame * eth;
	struct ip_datagram * ip;
	struct icmp_packet * icmp;
	
	eth = (struct ethernet_frame *) buffer;	
	ip = (struct ip_datagram *) eth->payload;
	icmp = (struct icmp_packet *) ip->payload;
	// in this way we know how to put every byte in our structure! Very light operation for the system
	
	int icmp_payload_size = 20; // default
	int timetolive = 128; // default
	if (argc == 3)
	{
		icmp_payload_size = atoi(argv[1]);
		timetolive = atoi(argv[2]);
	}

	if (argc == 2) icmp_payload_size = atoi(argv[1]);
		
	if (timetolive > 128) { perror("Time to live > 128. Return."); return -1; }
	if (icmp_payload_size >= MAX_LEN_BUFFER) { perror("icmp payload size greater than the maximum length of the buffer. Return."); return -1; }
	
	printf("payload size: %d\n", icmp_payload_size);
	forge_icmp_echo(icmp, icmp_payload_size);
	forge_ip(ip, 8 + icmp_payload_size, 1, *(unsigned int *) target_ip, timetolive); // proto = 1 according to iana.org/assignments/protocol-numbers
	forge_eth(eth, target_mac, 0x0800); // because the ulp is ip
	// I can put target_ip in forge_ip and modify the method in order to accept (unsigned char *) target_ip
	
	// printbuf to check if the packet is well formed before sending it in the net
	//printf("Sent the following buffer:\n");
	//printbuf(buffer, 42 + icmp_payload_size); // 14 for the eth header, 20 for the ip header, 8 for the icmp header, icmp_payload_size for the icmp payload	
	printf("Buffer sent.\nip->total_length = %d.\n", 14 + 28 + icmp_payload_size);
	
	t = sendto(s, buffer, 42 + icmp_payload_size, 0, (struct sockaddr *) &sll, len);
	if (t == -1) {perror("Sendto (IP) failed. Return."); return -1; }

	printf("Listen...\n");
	while(1) 
	{
		n = recvfrom(s, buffer, MAX_LEN_BUFFER, 0, (struct sockaddr *) &sll, &len);
		if (ntohs(eth->upper_layer_protocol) == 0x0800)
			if (are_equal(ip->source_address, (unsigned int *) target_ip, 4))
				if (ip->protocol == 1)
					if (icmp->type == 0 && ntohs(icmp->identifier) == 0x1234 && ntohs(icmp->sequence_number) == 1)
					{
						//printbuf(buffer, 42 + icmp_payload_size); 
						printf("Just received a packet with ip->total_length = %d\n", 14+ntohs(ip->total_length));
						//printf("time to live: %d\n", ip->time_to_live);
						break;
					}
	}
}

/*
	Conclusion:
	Sendto (IP) failed. Return.: Message too long 
	when I set icmp_packet_size >= 1473
*/