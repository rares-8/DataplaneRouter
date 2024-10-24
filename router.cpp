#include "lib.h"
#include "protocols.h"
#include <queue>
#include <arpa/inet.h>
#include <stdlib.h>
#include <stdio.h>
#include <iostream>
#include <string.h>
#include <bits/stdc++.h>
#include <fstream>
#include <bitset>
#include <unordered_map>

using namespace std;

#define HTYPE_ETHERNET 1
#define RTABLE_MAX_ENTRIES 100000
#define ETHERTYPE_IP 0x0800
#define ARP_ETHERTYPE 0x0806
#define ICMP_DEST_UNREACHABLE 3
#define ICMP_TIME_EXCEEDED 11
#define ICMP_CODE 0
#define ICMP_REPLY 0
#define MAC_SIZE 6
#define IPV4_SIZE 4
#define ARP_REQUEST 1
#define ARP_REPLY 2
#define MAX_TTL 64
#define ICMP 1


struct packet {
	int interface;
	char payload[MAX_PACKET_LEN];
	size_t packet_len;
};

// returns mask in cidr notation
int mask_to_cidr(uint32_t mask) {
	bitset<32> mask_bits(mask);
	int counter = 0;
	for (size_t i = 0; i < mask_bits.size(); i++) {
		if (mask_bits[i] == 0) {
			break;
		}
		counter++;
	}
	return counter;
}

struct trieNode {
	route_table_entry *entry;
	struct trieNode *left;
	struct trieNode *right;
	bool terminal;
};

struct trieNode *root;

queue<packet *> packet_queue;

struct route_table_entry *routing_table;
uint32_t rtable_len;

unordered_map<uint32_t, array<uint8_t, 6>> mac_table;

trieNode *initializeNode() {
	struct trieNode *new_trie_node = (struct trieNode *)malloc(sizeof(struct trieNode));
	DIE(new_trie_node == NULL, "failed to alocate memory");
	new_trie_node->entry = NULL;
	new_trie_node->left = NULL;
	new_trie_node->right = NULL;
	new_trie_node->terminal = false;
	return new_trie_node;
}

void insert_route(route_table_entry *route) {
	bitset<32> prefix_bits(route->prefix);
	int cidr_mask = mask_to_cidr(route->mask);
	struct trieNode *currentNode = root;

	for (int i = 0; i < cidr_mask; i++) {
		int value = prefix_bits[i];
		if (value == 1) {
			if (currentNode->right == NULL) {
				currentNode->right = initializeNode();
			}
			currentNode = currentNode->right;
		} else {
			if (currentNode->left == NULL) {
				currentNode->left = initializeNode();
			}
			currentNode = currentNode->left;
		}
	}
	currentNode->terminal = true;
	currentNode->entry = route;
}

/*
	Finds the best next route for the destination IP.
*/
struct route_table_entry *get_best_route(uint32_t destination_ip) {
	bitset<32> destination_bits(destination_ip);
	struct trieNode *currentNode = root;
	route_table_entry *best_route = NULL;

	for (int i = 0; i < 32; i++) {
		int value = destination_bits[i];
		if (currentNode == NULL) {
			break;
		}

		if (currentNode->entry != NULL) {
			best_route = currentNode->entry;
		}

		if (value == 1) {
			currentNode = currentNode->right;
		} else {
			currentNode = currentNode->left;
		}
	}

	return best_route;
}

/*
	Go through all packets in queue and check if the destination adress now has
	a known MAC adress. If it does, resend packet.
	If it does not, send it back at the end of the queue.
	ALL PACKETS IN QUEUE WILL MISS MAC DESTINATION
*/
void send_enqueued_packets() {
	size_t queue_size = packet_queue.size();
	size_t iterator = 0;

	while (iterator < queue_size) {
		struct packet *queued_packet = packet_queue.front();
		packet_queue.pop();

		struct ether_header *eth_hdr = (struct ether_header *) queued_packet->payload;
		struct iphdr *ip_hdr = (struct iphdr *)(queued_packet->payload + sizeof(struct ether_header));
		struct route_table_entry *best_route = get_best_route(ip_hdr->daddr);
		if (best_route == NULL) {
			iterator++;
			continue;
		}

		if (mac_table.find(best_route->next_hop) == mac_table.end()) {
			// send packet to the back of the queue
			packet_queue.push(queued_packet);
		} else {
			memcpy(eth_hdr->ether_dhost, mac_table.find(best_route->next_hop)->second.data(), sizeof(eth_hdr->ether_dhost));
			send_to_link(best_route->interface, queued_packet->payload, queued_packet->packet_len);
		}
		iterator++;
	}
}

// add entry to arp cache
void update_arp_table(struct packet *arp_packet) {
	struct arp_header *arp_hdr = (struct arp_header *)(arp_packet->payload + sizeof(struct ether_header));

	uint32_t source_ip = arp_hdr->spa;

	array<uint8_t, 6> searched_mac;
	copy(arp_hdr->sha, arp_hdr->sha + 6, searched_mac.begin());
	mac_table.insert(make_pair(source_ip, searched_mac));

	send_enqueued_packets();
}

void send_arp_reply(struct packet *packet) {
	struct ether_header *eth_hdr = (struct ether_header *) packet->payload;
	struct arp_header *arp_hdr = (struct arp_header *)(packet->payload + sizeof(struct ether_header));

	struct ether_header *new_ether_header = (struct ether_header *)calloc(1, sizeof(struct ether_header));
	DIE(new_ether_header == NULL, "memory allocation failed");

	new_ether_header->ether_type = htons(ARP_ETHERTYPE);
	get_interface_mac(packet->interface, new_ether_header->ether_shost);
	if (arp_hdr->tpa != inet_addr(get_interface_ip(packet->interface))) {
		return;
	}
	memcpy(new_ether_header->ether_dhost, eth_hdr->ether_shost, MAC_SIZE);

	// make reply header
	struct arp_header *new_arp_header = (struct arp_header *)calloc(1, sizeof(struct arp_header));
	DIE(new_arp_header == NULL, "memory allocation failed");

	new_arp_header->htype = htons(HTYPE_ETHERNET);
	new_arp_header->ptype = htons(ETHERTYPE_IP);
	new_arp_header->hlen = MAC_SIZE;
	new_arp_header->plen = IPV4_SIZE;
	new_arp_header->op = htons(ARP_REPLY);
	get_interface_mac(packet->interface, new_arp_header->sha);
	new_arp_header->spa = inet_addr(get_interface_ip(packet->interface));
	memcpy(new_arp_header->tha, arp_hdr->sha, MAC_SIZE);
	new_arp_header->tpa = arp_hdr->spa;

	uint32_t packet_length = sizeof(struct ether_header) + sizeof(struct arp_header);
	struct packet *arp_packet = (struct packet *)calloc(1, sizeof(struct packet));
	arp_packet->packet_len = packet_length;
	arp_packet->interface = packet->interface;
	memcpy(arp_packet->payload, new_ether_header, sizeof(struct ether_header));
	memcpy(arp_packet->payload + sizeof(struct ether_header), new_arp_header, sizeof(struct arp_header));
	send_to_link(arp_packet->interface, arp_packet->payload, packet_length);
}

void send_arp_request(struct packet *packet, uint8_t source_mac[6], uint32_t source_ip, uint32_t target_ip, struct route_table_entry *best_route) {
	struct arp_header arp_header;

	struct ether_header *new_ether_header = (struct ether_header *)calloc(1, sizeof(struct ether_header));

	new_ether_header->ether_type = htons(ARP_ETHERTYPE);
	get_interface_mac(best_route->interface, new_ether_header->ether_shost);
	uint8_t broadcast_mac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
	memcpy(new_ether_header->ether_dhost, broadcast_mac, MAC_SIZE);

	arp_header.htype = htons(HTYPE_ETHERNET);
	arp_header.ptype = htons(ETHERTYPE_IP);
	arp_header.hlen = MAC_SIZE;
	arp_header.plen = IPV4_SIZE;
	arp_header.op = htons(ARP_REQUEST);
	memcpy(arp_header.sha, source_mac, MAC_SIZE);
	arp_header.spa = source_ip;
	memset(arp_header.tha, 0, MAC_SIZE);
	arp_header.tpa = target_ip;

	uint32_t packet_length = sizeof(struct ether_header) + sizeof(struct arp_header);
	struct packet *arp_packet = (struct packet *)calloc(1, sizeof(struct packet));
	arp_packet->packet_len = packet_length;
	arp_packet->interface = best_route->interface;
	memcpy(arp_packet->payload, new_ether_header, sizeof(struct ether_header));
	memcpy(arp_packet->payload + sizeof(struct ether_header), &arp_header, sizeof(struct arp_header));

	// enqueue the packet until we receive the response for the ARP request
	packet_queue.push(packet);
	send_to_link(best_route->interface, arp_packet->payload, packet_length);
}

// send error message
void send_icmp_error(struct packet *packet, uint8_t error_type, uint8_t code) {
	struct iphdr *ip_hdr = (struct iphdr *)(packet->payload + sizeof(struct ether_header));

	bool request = false;

	// check if there is a route back to source
	struct route_table_entry *best_route = get_best_route(ip_hdr->saddr);
	if (best_route == NULL) {
		return;
	}

	/*
		First check if we have to make an ARP request. If we do, we leave destination
		MAC empty.
	*/
	if (mac_table.find(best_route->next_hop) == mac_table.end()) {
		request = true;
	}

	// new headers for packet
	struct ether_header *new_ether_header = (struct ether_header *)calloc(1, sizeof(struct ether_header));
	struct iphdr *new_ip_header = (struct iphdr *)calloc(1, sizeof(struct iphdr));
	struct icmphdr *new_icmp_header = (struct icmphdr *)calloc(1, sizeof(struct icmphdr));

	// build the ethernet packet
	get_interface_mac(best_route->interface, new_ether_header->ether_shost);
	new_ether_header->ether_type = htons(ETHERTYPE_IP);
	if (request == false) {
		memcpy(new_ether_header->ether_dhost, mac_table.find(best_route->next_hop)->second.data(), sizeof(new_ether_header->ether_dhost));
	} else {
		memset(new_ether_header->ether_dhost, 0, sizeof(new_ether_header->ether_dhost));
	}

	/* 
		ip_hdr total length =
		ip_hdr + 8 bytes from icmp(type, code, checksum and unused section) + old ip header + *8 bytes data from next protocol(if it exists)
	*/
	uint16_t total_length;
	bool ip_only = false;
	// if packet does not contain any data after IP
	if (packet->packet_len == sizeof(struct iphdr) + sizeof(struct ether_header)) {
		ip_only = true;
		total_length = sizeof(struct iphdr) + sizeof(struct icmphdr) + sizeof(struct iphdr);
	} else {
		total_length = sizeof(struct iphdr) + sizeof(struct icmphdr) + sizeof(struct iphdr) + sizeof(uint64_t);
	}

	new_ip_header->tot_len = htons(total_length);
	new_ip_header->daddr = ip_hdr->saddr;
	new_ip_header->saddr = inet_addr(get_interface_ip(best_route->interface));
	new_ip_header->check = 0;
	new_ip_header->tos = 0;
	new_ip_header->frag_off = 0;
	new_ip_header->version = 4;
	new_ip_header->ihl = 5;
	new_ip_header->id = 1;
	new_ip_header->ttl = MAX_TTL;
	new_ip_header->protocol = ICMP;
	new_ip_header->check = htons(checksum((uint16_t *)new_ip_header, sizeof(struct iphdr)));

	new_icmp_header->checksum = 0;
	new_icmp_header->type = error_type;
	new_icmp_header->code = code;

	size_t packet_length = sizeof(struct ether_header) + total_length;
	struct packet *new_packet = (struct packet *)calloc(1, sizeof(struct packet));
	new_packet->packet_len = packet_length;

	size_t offset = 0;
	memcpy(new_packet->payload, new_ether_header, sizeof(struct ether_header));
	offset = sizeof(struct ether_header);

	memcpy(new_packet->payload + offset, new_ip_header, sizeof(struct iphdr));
	offset += sizeof(struct iphdr);

	memcpy(new_packet->payload + offset, new_icmp_header, sizeof(struct icmphdr));
	offset += sizeof(struct icmphdr);

	memcpy(new_packet->payload + offset, ip_hdr, sizeof(struct iphdr));
	offset += sizeof(struct iphdr);

	// copy data contained in ip header (if there is any)
	if (ip_only == false) {
		memcpy(new_packet->payload + offset, packet->payload + sizeof(struct ether_header) + sizeof(struct iphdr), 8);
	}

	new_icmp_header = (struct icmphdr *)(new_packet->payload + sizeof(struct ether_header) + sizeof(struct iphdr));
	uint32_t icmp_header_size = 4 * sizeof(uint32_t) + sizeof(struct iphdr);
	new_icmp_header->checksum = htons(checksum((uint16_t *)new_icmp_header, icmp_header_size));

	// check if we need to make a request
	if (request == false) {
		send_to_link(best_route->interface, new_packet->payload, packet_length);
	} else {
		send_arp_request(new_packet, new_ether_header->ether_shost, new_ip_header->saddr, best_route->next_hop, best_route);
	}
}

void send_icmp_reply(struct packet *packet) {
	struct iphdr *ip_hdr = (struct iphdr *)(packet->payload + sizeof(struct ether_header));
	struct icmphdr *icmp_hdr = (struct icmphdr *)(packet->payload + sizeof(struct ether_header) + sizeof(struct iphdr));

	bool request = false;

	// check if there is a route back to source
	struct route_table_entry *best_route = get_best_route(ip_hdr->saddr);
	if (best_route == NULL) {
		return;
	}

	/*
		First check if we have to make an ARP request. If we do, we leave destination
		MAC empty.
	*/
	if (mac_table.find(best_route->next_hop) == mac_table.end()) {
		request = true;
	}

	// new headers for packet
	struct ether_header *new_ether_header = (struct ether_header *)calloc(1, sizeof(struct ether_header));
	struct iphdr *new_ip_header = (struct iphdr *)calloc(1, sizeof(struct iphdr));
	struct icmphdr *new_icmp_header = (struct icmphdr *)calloc(1, sizeof(struct icmphdr));

	// build the ethernet packet
	get_interface_mac(best_route->interface, new_ether_header->ether_shost);
	new_ether_header->ether_type = htons(ETHERTYPE_IP);
	if (request == false) {
		memcpy(new_ether_header->ether_dhost, mac_table.find(best_route->next_hop)->second.data(), sizeof(new_ether_header->ether_dhost));
	} else {
		memset(new_ether_header->ether_dhost, 0, sizeof(new_ether_header->ether_dhost));
	}

	uint16_t total_length = sizeof(struct iphdr) + sizeof(struct icmphdr);
	// add data
	total_length += packet->packet_len - sizeof(struct icmphdr) - sizeof(struct iphdr) - sizeof(ether_header);

	new_ip_header->tot_len = htons(total_length);
	new_ip_header->daddr = ip_hdr->saddr;
	new_ip_header->saddr = inet_addr(get_interface_ip(best_route->interface));
	new_ip_header->check = 0;
	new_ip_header->tos = 0;
	new_ip_header->frag_off = 0;
	new_ip_header->version = 4;
	new_ip_header->ihl = 5;
	new_ip_header->id = 1;
	new_ip_header->ttl = MAX_TTL;
	new_ip_header->protocol = ICMP;
	new_ip_header->check = htons(checksum((uint16_t *)new_ip_header, sizeof(struct iphdr)));

	// build ICMP header
	new_icmp_header->checksum = 0;
	new_icmp_header->un.echo.id = icmp_hdr->un.echo.id;
	new_icmp_header->un.echo.sequence = icmp_hdr->un.echo.sequence;
	new_icmp_header->type = ICMP_REPLY;
	new_icmp_header->code = ICMP_CODE;

	size_t packet_length = sizeof(struct ether_header) + total_length;
	struct packet *new_packet = (struct packet *)calloc(1, sizeof(struct packet));
	new_packet->packet_len = packet_length;

	size_t offset = 0;
	memcpy(new_packet->payload, new_ether_header, sizeof(struct ether_header));
	offset = sizeof(struct ether_header);

	memcpy(new_packet->payload + offset, new_ip_header, sizeof(struct iphdr));
	offset += sizeof(struct iphdr);

	memcpy(new_packet->payload + offset, new_icmp_header, sizeof(struct icmphdr));
	offset += sizeof(struct icmphdr);

	// copy data after ICMP
	memcpy(new_packet->payload + offset, packet->payload + sizeof(struct ether_header) + sizeof(struct iphdr) +
	sizeof(struct icmphdr), packet->packet_len - sizeof(struct ether_header) - sizeof(struct iphdr) - sizeof(struct icmphdr));

	new_icmp_header = (struct icmphdr *)(new_packet->payload + sizeof(struct ether_header) + sizeof(struct iphdr));
	uint32_t icmp_header_size = 2 * sizeof(uint32_t) + packet->packet_len - sizeof(struct ether_header) - sizeof(struct iphdr) - sizeof(struct icmphdr);
	new_icmp_header->checksum = htons(checksum((uint16_t *)new_icmp_header, icmp_header_size));

	// check if we need to make a request
	if (request == false) {
		send_to_link(best_route->interface, new_packet->payload, packet_length);
	} else {
		send_arp_request(new_packet, new_ether_header->ether_shost, new_ip_header->saddr, best_route->next_hop, best_route);
	}
}

void forward_packet(struct packet *packet, struct route_table_entry *best_route) {
	struct ether_header *eth_hdr = (struct ether_header *) packet->payload;
	struct iphdr *ip_hdr = (struct iphdr *)(packet->payload + sizeof(struct ether_header));

	// if best route is not yet calculated, calculate it
	if (best_route == NULL) {
		best_route = get_best_route(ip_hdr->daddr);
	}

	// if best route is not found, then send ICMP error
	if (best_route == NULL) {
		send_icmp_error(packet, ICMP_DEST_UNREACHABLE, ICMP_CODE);
		return;
	}

	// if ttl <= 1, send ICMP error
	if (ip_hdr->ttl <= 1) {
		send_icmp_error(packet, ICMP_TIME_EXCEEDED, ICMP_CODE);
		return;
	}

	// check if checksum is good
	uint16_t old_checksum = ip_hdr->check;
	ip_hdr->check = 0;
	uint16_t new_checksum = checksum((uint16_t *)ip_hdr, sizeof(struct iphdr));
	ip_hdr->check = htons(new_checksum);
	if (old_checksum != ip_hdr->check) {
		return;
	}

	ip_hdr->ttl--;
	// recalculate checksum
	ip_hdr->check = 0;
	ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));

	// calculate source mac
	uint8_t source_mac[8];
	get_interface_mac(best_route->interface, source_mac);
	memcpy(eth_hdr->ether_shost, source_mac, sizeof(eth_hdr->ether_shost));

	// check if we know MAC for next hop
	if (mac_table.find(best_route->next_hop) == mac_table.end()) {
		// leave destination MAC empty
		memset(eth_hdr->ether_dhost, 0, sizeof(eth_hdr->ether_dhost));
		uint32_t source_ip = inet_addr(get_interface_ip(best_route->interface));
		send_arp_request(packet, source_mac, source_ip, best_route->next_hop, best_route);
		return;
	} else {
		memcpy(eth_hdr->ether_dhost, mac_table.find(best_route->next_hop)->second.data(), sizeof(eth_hdr->ether_dhost));
	}
	
	send_to_link(best_route->interface, packet->payload, packet->packet_len);
}

void process_icmp(struct packet *packet) {
	struct iphdr *ip_hdr = (struct iphdr *)(packet->payload + sizeof(struct ether_header));

	// check if checksum is good
	uint16_t old_checksum = ip_hdr->check;
	ip_hdr->check = 0;
	uint16_t new_checksum = checksum((uint16_t *)ip_hdr, sizeof(struct iphdr));
	ip_hdr->check = htons(new_checksum);
	if (old_checksum != ip_hdr->check) {
		return;
	}

	if (ip_hdr->ttl <= 1) {
		send_icmp_error(packet, ICMP_TIME_EXCEEDED, ICMP_CODE);
		return;
	}

	// check if there is a route to the destination
	struct route_table_entry *best_route = get_best_route(ip_hdr->daddr);
	// if there is no route to destination, send error back to source
	if (best_route == NULL) {
		send_icmp_error(packet, ICMP_DEST_UNREACHABLE, ICMP_CODE);
		return;
	}
	
	// check if packet is meant for the router
	uint32_t router_ip = inet_addr(get_interface_ip(packet->interface));
	if (router_ip == ip_hdr->daddr) {
		send_icmp_reply(packet);
		return;
	}

	// valid ICMP packet, simply forward it
	forward_packet(packet, best_route);
}


int main(int argc, char *argv[])
{	
	init(argc - 2, argv + 2);

	routing_table = (route_table_entry *)malloc(sizeof(struct route_table_entry) * RTABLE_MAX_ENTRIES);
	DIE(routing_table == NULL, "memory allocation failed");
	rtable_len = read_rtable(argv[1], routing_table);
	
	// build trie
	root = initializeNode();
	for (uint32_t i = 0; i < rtable_len; i++) {
		insert_route(&routing_table[i]);
	}

	while (1) {
		struct packet *packet = (struct packet *)calloc(1, sizeof(struct packet));
		DIE(packet == NULL, "memory allocation failed");
		packet->interface = recv_from_any_link(packet->payload, &packet->packet_len);
		// extract the ethernet header
		struct ether_header *eth_hdr = (struct ether_header *) packet->payload;

		// we got an IP message
		if (ntohs(eth_hdr->ether_type) == ETHERTYPE_IP) {
			struct iphdr *ip_hdr = (struct iphdr *)(packet->payload + sizeof(struct ether_header));
			if (ip_hdr->protocol == ICMP) {
				process_icmp(packet);
			} else {
				forward_packet(packet, NULL);
			}
		} else if (ntohs(eth_hdr->ether_type) == ARP_ETHERTYPE) {
			struct arp_header *arp_hdr = (struct arp_header *)(packet->payload + sizeof(struct ether_header));
			if (ntohs(arp_hdr->op) == ARP_REQUEST) {
				send_arp_reply(packet);
			} else if (ntohs(arp_hdr->op) == ARP_REPLY) {
				update_arp_table(packet);
			}
		}
	}
	return 0;
}
