#include "fw.h"
#include "log.h"
#include "rules_table.h"
#include "connections.h"
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/string.h>

#define SUCCESS 	(0)
#define FAILURE	       (-1)
#define TRUE		(1)
#define FALSE		(0)


/**
* A function which receives a packet and returns its verdict (Accpet / Drop)
*/
unsigned int packet_verdict(rule_t *rules_table, int rules_num, struct sk_buff *skb, direction_t direction, log_t *log, conns_table_t *connections_table)
{
	int i;
	int insertion_status;
	struct iphdr *ip_header = (struct iphdr *) skb_network_header(skb);
	packet_t packet_struct;
	packet_t *packet = &packet_struct;
	struct tcphdr *tcp_header = NULL;
	struct udphdr *udp_header = NULL;	
	reason_t verdict_reason;
	__be32 loopback_routing_prefix = 127; /* Stores 127.0.0.0 in network byte order (Loopback routing prefix) */
	__be32 loopback_netmask = 255; /* Stores 255.0.0.0 in network byte order (Same as /8 CIDR notation) */
	unsigned int verdict;

	/* Check if the packet isn't IPv4 */
	if (ip_header->version != IP_VERSION)
	{
		/* Accept packet without logging */
		return NF_ACCEPT;
	}

	packet->protocol = ip_header->protocol;
	packet->direction = direction;
	/* Check if the packet isn't ICMP / TCP / UDP */
	if (packet->protocol != PROT_ICMP && packet->protocol != PROT_TCP && packet->protocol != PROT_UDP)
	{
		/* Accept packet without logging */
		return NF_ACCEPT;
	}
	
	packet->src_ip = ip_header->saddr;
	packet->dst_ip = ip_header->daddr;
	/* Check if the packet is loopback */
	if ((packet->src_ip & loopback_netmask) == loopback_routing_prefix && (packet->dst_ip & loopback_netmask) == loopback_routing_prefix)
	{
		/* Accept packet without logging */
		return NF_ACCEPT;
	}

	/* Extract data from transport header */
	if (packet->protocol == PROT_TCP)
	{
		tcp_header = (struct tcphdr *) skb_transport_header(skb);

		packet->src_port = ntohs(tcp_header->source);
		packet->dst_port = ntohs(tcp_header->dest);	
		
		packet->syn = tcp_header->syn;
		packet->ack = tcp_header->ack;
		packet->rst = tcp_header->rst;
		packet->fin = tcp_header->fin;
		packet->psh = tcp_header->psh;
		packet->urg = tcp_header->urg;
		
		/* Check if the packet is a Christmas tree packet */
		if ((packet->fin == 1) && (packet->urg == 1) && (packet->psh == 1))
		{
			verdict_reason = REASON_XMAS_PACKET;
			verdict = NF_DROP;
			log_packet(log, packet, verdict_reason, verdict);
			return verdict;
		}

		/* Check if the packet is part of a TCP connection */
        	/* If it's a SYN packet which initializes a FTP data connection (as part of a valid FTP connection) */
       		if (packet->ack == 0)
        	{
		    	verdict = tcp_packet_verdict(connections_table, packet, direction);

			/* Based on the fact the new connection row is insterted from the proxy */
		    	if (verdict == NF_ACCEPT)
		    	{
				/* It is part of a valid TCP connection */
				verdict_reason = REASON_LEGAL_TCP_STATE;
				/* If the packet is a FTP / HTTP / SMTP packet, send the packet to the userspace proxy server */
				/* Check if the packet is sent to the proxy from the server or from the client */
				if (/*packet->src_port == HTTP_PORT ||*/ packet->src_port == FTP_PORT)
				{
				    	from_server_to_proxy(skb, direction);
				}
				else if (/*packet->dst_port == HTTP_PORT ||*/ packet->dst_port == FTP_PORT)
				{
					from_client_to_proxy(skb, direction, packet->dst_port);
				}

				log_packet(log, packet, verdict_reason, verdict);

				return NF_ACCEPT;
		    	}
        	}
        	/* If it's an ACK=1 packet */
		if (packet->ack == 1)
        	{
			verdict = tcp_packet_verdict(connections_table, packet, direction);

			if (verdict == NF_ACCEPT)
			{
				verdict_reason = REASON_LEGAL_TCP_STATE;
				/* If the packet is a FTP / HTTP / SMTP packet, send the packet to the userspace proxy server */
				if (packet->src_port == HTTP_PORT || packet->src_port == FTP_PORT || packet->src_port == SMTP_PORT)
				{
				    	from_server_to_proxy(skb, direction);
				}
				else if (packet->dst_port == HTTP_PORT || packet->dst_port == FTP_PORT || packet->dst_port == SMTP_PORT)
				{
				    	from_client_to_proxy(skb, direction, packet->dst_port);
				}
			}
			else
			{
				verdict_reason = REASON_ILLEGAL_TCP_STATE;
			}

			log_packet(log, packet, verdict_reason, verdict);

			return verdict /*CHANGE THIS*/;
		}

	}
	else if(packet->protocol == PROT_UDP)
	{
		udp_header = (struct udphdr *) skb_transport_header(skb);
		packet->src_port = ntohs(udp_header->source);
		packet->dst_port = ntohs(udp_header->dest);	
	}
	
	/* Iterate the rules table from top to bottom */
	for(i=0; i<rules_num; ++i)
	{	
		if (is_rule_matching(packet, &(rules_table[i])) == TRUE)
		{
			/* If found for the packet a matching rule, set the rule index as the reason and return the rule index */
			verdict_reason = i;
			verdict = rules_table[i].action;
			/* Check if the packet is initializing a TCP connection */
			if (verdict == NF_ACCEPT && packet->protocol == PROT_TCP)
			{
				/* If it's a SYN packet */
				if (packet->syn == 1 && packet->ack == 0 && packet->rst == 0 && packet->fin == 0)
				{
					/* Add a new TCP connection to the connections table */
					insertion_status = insert_connection_row(connections_table, packet, direction);
					if (insertion_status < 0)
					{
						verdict = NF_DROP;
						verdict_reason = REASON_CANT_ADD_CONNECTION;
					}
				}
				
				/* If the packet is a FTP / HTTP / SMTP packet, send the packet to the userspace proxy server */
				if (packet->src_port == HTTP_PORT || packet->src_port == FTP_PORT || packet->src_port == SMTP_PORT)
				{
					from_server_to_proxy(skb, direction);
				}
				else if (packet->dst_port == HTTP_PORT || packet->dst_port == FTP_PORT || packet->dst_port == SMTP_PORT)
				{
					from_client_to_proxy(skb, direction, packet->dst_port);
				}
			}
			log_packet(log, packet, verdict_reason, verdict); // Log the packet

			return verdict;
		}
	}
	/* If got here, no rule matched */
	verdict_reason = REASON_NO_MATCHING_RULE;
	verdict = NF_DROP;
	log_packet(log, packet, verdict_reason, verdict); // Log the packet
	return verdict;
}

/**
* A function which checks if a specified rule matches the given packet
*/
int is_rule_matching(packet_t *packet, rule_t *rule)
{	
	flag_t rule_ack;

	/* Compare direction field */
	if (rule->direction != DIRECTION_ANY && packet->direction != rule->direction)
	{ return FALSE; /* There's no match */ }

	/* Compare source and destination ip addresses */
	if ((packet->src_ip & rule->src_prefix_mask) != (rule->src_ip & rule->src_prefix_mask))
	{ return FALSE; }

	if ((packet->dst_ip & rule->dst_prefix_mask) != (rule->dst_ip & rule->dst_prefix_mask))
	{ return FALSE; }

	/* For non ICMP packet, compare source and destination ports */
	if (packet->protocol != PROT_ICMP)
	{
		/* Compare source port */
		if (rule->src_port != PORT_ANY)
		{
			if (rule->src_port == PORT_ABOVE_1023 && packet->src_port <= 1023)
			{ return FALSE; }
			if (rule->src_port != PORT_ABOVE_1023 && packet->src_port != rule->src_port)
			{ return FALSE; }
		}
		/* Compare destination port */
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
		if (rule->ack != ACK_ANY)
		{
			rule_ack = (flag_t) (rule->ack - 1);
			if (rule_ack != packet->ack)
			{ return FALSE; }
		}
	}

	return TRUE; /* Match found! */
}

/**
* A function which checks if a given rule is valid
*/
int is_valid_rule(rule_t *rule)
{
	/* Check direction field value */
	if (rule->direction != DIRECTION_IN && rule->direction != DIRECTION_OUT && rule->direction != DIRECTION_ANY)
	{ 
		return FALSE; 
	}
	/* Check source & destination cidr notation values */
	if (rule->src_prefix_size < 0 || rule->src_prefix_size > 32)
	{
		return FALSE;
	}
	if (rule->dst_prefix_size < 0 || rule->dst_prefix_size > 32)
	{ 
		return FALSE;
	}
	/* Check source & destination port values */
	if (rule->src_port < 0)
	{ 
		return FALSE; 
	}	
	if (rule->dst_port < 0)
	{ 
		return FALSE; 
	}
	/* Check protocol field value */
	if (rule->protocol != PROT_ICMP && rule->protocol != PROT_TCP && rule->protocol != PROT_UDP && rule->protocol != PROT_ANY)
	{ 
		return FALSE; 
	}
	/* Check ACK field value */
	if (rule->ack != ACK_NO && rule->ack != ACK_YES && rule->ack != ACK_ANY)
	{ 
		return FALSE; 
	}
	/* Check action field value */
	if (rule->action != NF_ACCEPT && rule->action != NF_DROP)
	{ 
		return FALSE; 
	}

	return TRUE; /* the given rule is valid */
}

void from_client_to_proxy(struct sk_buff *skb, direction_t direction, __be16 packet_dst_port)
{
	struct iphdr *ip_header = (struct iphdr *) skb_network_header(skb);
	struct tcphdr *tcp_header = (struct tcphdr *) skb_transport_header(skb);
	/*__be32 localhost_ip = 16777343; */
	__be32 inner_localhost = 50397450; /* Stores 10.1.1.3 (IP of this machine in the LAN) in network byte order */
	__be32 outer_localhost = 50462986; /* Stores 10.1.2.3 (IP of this machine outside the LAN) in network byte order */

	if (packet_dst_port == HTTP_PORT)
	{
		tcp_header->dest = htons(HTTP_PROXY_PORT);
	}

	else if (packet_dst_port == FTP_PORT)
	{
		tcp_header->dest = htons(FTP_PROXY_PORT);
	}

	else // packet_dst_port == SMTP_PORT
	{
		tcp_header->dest = htons(SMTP_PROXY_PORT);
	}

	if (direction == DIRECTION_IN)
	{
		ip_header->daddr = outer_localhost;
	}
	else
	{
		ip_header->daddr = inner_localhost;
	}

	correct_checksum(skb);
}

void from_server_to_proxy(struct sk_buff *skb, direction_t direction)
{
	struct iphdr *ip_header = (struct iphdr *) skb_network_header(skb);
	__be32 inner_localhost = 50397450; /* Stores 10.1.1.3 (IP of this machine in the LAN) in network byte order */
	__be32 outer_localhost = 50462986; /* Stores 10.1.2.3 (IP of this machine outside the LAN) in network byte order */

	if (direction == DIRECTION_IN)
	{
		ip_header->daddr = outer_localhost;
	}
	else
	{
		ip_header->daddr = inner_localhost;
	}

	correct_checksum(skb);
}

void correct_checksum(struct sk_buff *skb)
{
	struct iphdr *ip_header = (struct iphdr *) skb_network_header(skb);
	struct tcphdr *tcp_header = (struct tcphdr *) skb_transport_header(skb);
	int tcp_len;

	/* Fix IP header checksum */
	ip_header->check = 0;
	ip_header->check = ip_fast_csum((u8 *) ip_header, ip_header->ihl);

	skb->ip_summed = CHECKSUM_NONE; // No checksum assistance
	skb->csum_valid = 0;

	/* Linearize the sk_buff */
	if (skb_linearize(skb) < 0)
	{
		return;
	}

	/* Re-take headers. The linearize may change skbs pointers */
	ip_header = ip_hdr(skb);
	tcp_header = tcp_hdr(skb);

	/* Fix TCP header checksum */
	tcp_len = (ntohs(ip_header->tot_len) - ((ip_header->ihl) << 2));
	tcp_header->check = 0;
	tcp_header->check = tcp_v4_check(tcp_len, ip_header->saddr, ip_header->daddr, csum_partial((char *)tcp_header, tcp_len, 0));
}


