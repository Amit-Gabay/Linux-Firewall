#include "fw.h"
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/string.h>

#define SUCCESS (0)
#define FAILURE (-1)

int packet_verdict(rule_t *rules_table, int rules_num, struct sk_buff *skb, direction_t packet_direction);
int find_match(rule_t *rules_table, int rules_num, struct sk_buff *skb, direction_t direction);
int is_valid_rule(rule_t *rules_table, int rule_index);
int check_matching(packet_t *packet, rule_t *rule);


int packet_verdict(rule_t *rules_table, int rules_num, struct sk_buff *skb, direction_t packet_direction)
{
	__be16 protocol;
	int matched_rule_index;
	struct iphdr *ip_header = (struct iphdr *) skb_network_header(skb);

	if (ip_header->version != 4)
	{
		return NF_ACCEPT;
	}

	protocol = ip_header->protocol;
	if (protocol != 1 /*ICMP*/ && protocol != 6 /*TCP*/ && protocol != 17 /*UDP*/)
	{
		return NF_ACCEPT;
	}

	/* Else, we have to find a match in the rules table */
	matched_rule_index = find_match(rules_table, rules_num, skb, packet_direction);
	if (matched_rule_index == -1)
	{
		return NF_DROP;
	}
	
	/* Return the action of the matching rule in the rules table */
	return rules_table[matched_rule_index].action;
}

int find_match(rule_t *rules_table, int rules_num, struct sk_buff *skb, direction_t direction)
{
	int i;
	struct iphdr *ip_header = (struct iphdr *) skb_network_header(skb);
	packet_t packet_struct;
	packet_t *packet = &packet_struct;
	struct tcphdr *tcp_header = NULL;
	struct udphdr *udp_header = NULL;
	
	packet->src_ip = ip_header->saddr;
	packet->dst_ip = ip_header->daddr;
	packet->protocol = ip_header->protocol;

	/* Extract data from packet */
	if (packet->protocol == 1 /*ICMP*/)
	{
		/* Do nothing */	
	}
	else if (packet->protocol == 6 /*TCP*/)
	{
		tcp_header = (struct tcphdr *) skb_transport_header(skb);
		packet->src_port = tcp_header->source;
		packet->dst_port = tcp_header->dest;	
		packet->ack = tcp_header -> ack;
	}
	else /*UDP*/
	{
		udp_header = (struct udphdr *) skb_transport_header(skb);
		packet->src_port = udp_header->source;
		packet->dst_port = udp_header->dest;	
	}
	
	/* Iterate rules table from top to bottom */
	for(i=0; i<rules_num; ++i)
	{	
		if (check_matching(packet, &(rules_table[i])) == 1)
		{
			return i;
		}
	}
	return FAILURE;	/* No match found - Something went wrong */
}

int check_matching(packet_t *packet, rule_t *rule)
{	
	if (packet->direction != rule->direction)
	{ return FAILURE; } /* There's no match */

	if ((packet->src_ip & rule->src_prefix_mask) != (rule->src_ip & rule->src_prefix_mask))
	{ return FAILURE; }

	if ((packet->dst_ip & rule->dst_prefix_mask) != (rule->dst_ip & rule->dst_prefix_mask))
	{ return FAILURE; }

	if (packet->protocol != 1 /*ICMP*/)
	{
		if (rule->src_port > 0)
		{
			if (rule->src_port == 1023 && packet->src_port <= 1023)
			{ return FAILURE; }
			if (rule->src_port < 1023 && packet->src_port != rule->src_port)
			{ return FAILURE; }
		}

		if (rule->dst_port > 0)
		{
			if (rule->dst_port == 1023 && packet->dst_port <= 1023)
			{ return FAILURE; }
			if (rule->dst_port < 1023 && packet->dst_port != rule->dst_port)
			{ return FAILURE; }
		}
	}
	
	if ((rule->protocol != 0x03) && (rule->protocol != packet->protocol))
	{ return FAILURE; }

	if (rule->protocol == 255 && (packet->protocol != 1 && packet->protocol != 6 && packet->protocol != 17))
	{ return FAILURE; }
	
	if ((rule->protocol != 143 && rule->protocol != 255) && (packet->protocol != rule->protocol))
	{ return FAILURE; }	

	return SUCCESS; /* Match found! */
}

int is_valid_rule(rule_t *rules_table, int rule_index)
{
	rule_t *rule = &rules_table[rule_index];
	if (rule->direction != 0x01 && rule->direction != 0x02 && rule->direction != 0x03)
	{ 
		return FAILURE; 
	}

	if (rule->src_prefix_size < 0 || rule->src_prefix_size > 32)
	{
		return FAILURE;
	}

	if (rule->dst_prefix_size < 0 || rule->dst_prefix_size > 32)
	{ 
		return FAILURE;
	}

	if (ntohs(rule->src_port) < 0 || ntohs(rule->src_port) > 1023)
	{ 
		return FAILURE; 
	}
	
	if (ntohs(rule->dst_port) < 0 || ntohs(rule->dst_port) > 1023)
	{ 
		return FAILURE; 
	}

	if (rule->protocol != 1 && rule->protocol != 6 && rule->protocol != 17 && rule->protocol != 143 && rule->protocol != 255)
	{ 
		return FAILURE; 
	}

	if (rule->ack != 0x01 && rule->ack != 0x02 && rule->ack != 0x03)
	{ 
		return FAILURE; 
	}
	
	if (rule->action != NF_ACCEPT && rule->action != NF_DROP)
	{ 
		return FAILURE; 
	}

	return SUCCESS;
}





