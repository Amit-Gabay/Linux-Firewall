#include "fw.h"
#include "log.h"
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/string.h>

#define SUCCESS 	(0)
#define FAILURE	       (-1)
#define TRUE		(1)
#define FALSE		(0)

unsigned int packet_verdict(rule_t *rules_table, int rules_num, struct sk_buff *skb, direction_t packet_direction, log_t *log);
int is_valid_rule(rule_t *rules_table, int rule_index);
int is_rule_matching(packet_t *packet, rule_t *rule);


unsigned int packet_verdict(rule_t *rules_table, int rules_num, struct sk_buff *skb, direction_t direction, log_t *log)
{
	int i;
	struct iphdr *ip_header = (struct iphdr *) skb_network_header(skb);
	packet_t packet_struct;
	packet_t *packet = &packet_struct;
	struct tcphdr *tcp_header = NULL;
	struct udphdr *udp_header = NULL;	
	reason_t verdict_reason;
	unsigned int verdict;

	if (ip_header->version != IP_VERSION)
	{
		/* Accept packet without logging */
		return NF_ACCEPT;
	}

	packet->protocol = ip_header->protocol;
	if (packet->protocol != PROT_ICMP && packet->protocol != PROT_TCP && packet->protocol != PROT_UDP)
	{
		/* Accept packet without logging */
		return NF_ACCEPT;
	}
	
	packet->src_ip = ip_header->saddr;
	packet->dst_ip = ip_header->daddr;
	/* CHECK IF LOOPBACK */

	/* Extract data from packet */
	if (packet->protocol == PROT_ICMP)
	{
		/* Do nothing */	
	}
	else if (packet->protocol == PROT_TCP)
	{
		tcp_header = (struct tcphdr *) skb_transport_header(skb);

		if ((tcp_header->fin == 1) && (tcp_header->urg == 1) && (tcp_header->psh == 1))
		{
			verdict_reason = REASON_XMAS_PACKET;
			verdict = NF_DROP;
			log_packet(log, packet, verdict_reason, verdict);
			return verdict;
		}

		packet->src_port = ntohs(tcp_header->source);
		packet->dst_port = ntohs(tcp_header->dest);	
		packet->ack = tcp_header->ack;
	}
	else /*UDP*/
	{
		udp_header = (struct udphdr *) skb_transport_header(skb);
		packet->src_port = ntohs(udp_header->source);
		packet->dst_port = ntohs(udp_header->dest);	
	}
	
	/* Iterate rules table from top to bottom */
	for(i=0; i<rules_num; ++i)
	{	
		if (is_rule_matching(packet, &(rules_table[i])) == TRUE)
		{
			/* If found for the packet a matching rule, set the rule index as the reason and return the rule index */
			verdict_reason = i;
			verdict = rules_table[i].action;
			log_packet(log, packet, verdict_reason, verdict);
			return verdict;
		}
	}
	verdict_reason = REASON_NO_MATCHING_RULE;
	verdict = NF_DROP;
	log_packet(log, packet, verdict_reason, verdict);
	return verdict;	/* No matching rule found for the packet */
}

/* A function which compares the each field of the packet to its corresponding rule field */
int is_rule_matching(packet_t *packet, rule_t *rule)
{	
	/* Compare direction field */
	if (rule->direction != DIRECTION_ANY && packet->direction != rule->direction)
	{ return FALSE; } /* There's no match */

	/* Compare source and destination ip addresses */
	if ((packet->src_ip & rule->src_prefix_mask) != (rule->src_ip & rule->src_prefix_mask))
	{ return FALSE; }

	if ((packet->dst_ip & rule->dst_prefix_mask) != (rule->dst_ip & rule->dst_prefix_mask))
	{ return FALSE; }

	/* For non ICMP packet, compare source and destination ports */
	if (packet->protocol != PROT_ICMP)
	{
		if (rule->src_port != PORT_ANY);
		{
			if (rule->src_port == PORT_ABOVE_1023 && packet->src_port <= 1023)
			{ return FALSE; }
			if (rule->src_port != PORT_ABOVE_1023 && packet->src_port != rule->src_port)
			{ return FALSE; }
		}

		if (rule->dst_port != PORT_ANY)
		{
			if (rule->dst_port == PORT_ABOVE_1023 && packet->dst_port <= 1023)
			{ return FALSE; }
			if (rule->dst_port != PORT_ABOVE_1023 && packet->dst_port != rule->dst_port)
			{ return FALSE; }
		}
	}
	
	/* Compare protocol field */
	if ((rule->protocol != PROT_ANY) && (rule->protocol != packet->protocol))
	{ return FALSE; }

	/* For TCP packet, compare ACK flag */
	if (packet->protocol == PROT_TCP)
	{
		if (rule->ack != packet->ack)
		{
			return FALSE;
		}
	}

	return TRUE; /* Match found! */
}

int is_valid_rule(rule_t *rules_table, int rule_index)
{
	rule_t *rule = &rules_table[rule_index];
	if (rule->direction != DIRECTION_IN && rule->direction != DIRECTION_OUT && rule->direction != DIRECTION_ANY)
	{ 
		return FALSE; 
	}

	if (rule->src_prefix_size < 0 || rule->src_prefix_size > 32)
	{
		return FALSE;
	}

	if (rule->dst_prefix_size < 0 || rule->dst_prefix_size > 32)
	{ 
		return FALSE;
	}

	if (rule->src_port < 0)
	{ 
		return FALSE; 
	}
	
	if (rule->dst_port < 0)
	{ 
		return FALSE; 
	}

	if (rule->protocol != PROT_ICMP && rule->protocol != PROT_TCP && rule->protocol != PROT_UDP && rule->protocol != PROT_ANY)
	{ 
		return FALSE; 
	}

	if (rule->ack != ACK_NO && rule->ack != ACK_YES && rule->ack != ACK_ANY)
	{ 
		return FALSE; 
	}
	
	if (rule->action != NF_ACCEPT && rule->action != NF_DROP)
	{ 
		return FALSE; 
	}

	return TRUE;
}





