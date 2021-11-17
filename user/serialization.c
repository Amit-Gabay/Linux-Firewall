#include "serialization.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

static unsigned int cidr_to_mask(unsigned int cidr);

int print_rules(char *buffer, size_t buffer_size)
{
	char *rules[MAX_RULES];
	int rules_num = 0;
	int i;
	size_t rule_size = sizeof(rule_t);
	size_t bytes_left = buffer_size;

	while (bytes_left >= rule_size)
	{
		rules[rules_num] = (char *) malloc(rule_size);
		memcpy(rules[rules_num], buffer, rule_size);
		bytes_left -= rule_size;
		buffer += rule_size;
		++rules_num;
	}
	if (bytes_left > 0)
	{ return -1; }

	for (i=0; i<rules_num; ++i)
	{
		print_single_rule((rule_t *) rules[i]);
		free(rules[i]);
	}
	return 0;
}

void print_single_rule(rule_t *rule)
{
	char rule_string[90]; /* Each printed rule shouldn't take more than 90 characters */
	char *name = rule->rule_name;
	char *direction;
	char src_ip[19];
	char dst_ip[19];
	char *protocol;
	char src_port[6];
	char dst_port[6];
	char textual_src_ip[16];
	char textual_dst_ip[16];
	char *ack;
	char *action;

	/* Convert direction to string */
	if (rule->direction == DIRECTION_IN)
	{ direction = "in"; }
	else if (rule->direction == DIRECTION_OUT)
	{ direction = "out"; }
	else
	{ direction = "any"; }
	
	/* Convert src_ip to string */
	if (rule->src_prefix_size == 0)
	{
		sprintf(src_ip, "any");
	}
	else
	{
		inet_ntop(AF_INET, &rule->src_ip, textual_src_ip, 16);
		sprintf(src_ip, "%s/%u", textual_src_ip, rule->src_prefix_size);
	}

	/* Convert dst_ip to string */
	if (rule->dst_prefix_size == 0)
	{
		sprintf(dst_ip, "any");
	}
	else
	{
		inet_ntop(AF_INET, &rule->dst_ip, textual_dst_ip, 16);
		sprintf(dst_ip, "%s/%u", textual_dst_ip, rule->dst_prefix_size);
	}

	/* Convert protocol to string */
	if (rule->protocol == PROT_ICMP)
	{ protocol = "ICMP"; }
	else if (rule->protocol == PROT_TCP)
	{ protocol = "TCP"; }
	else
	{ protocol = "any"; }

	/* Convert src_port to string */
	if (ntohs(rule->src_port) == 0)
	{
		sprintf(src_port, "any");
	}
	else if (ntohs(rule->src_port) == 1023)
	{
		sprintf(src_port, ">1023");
	}
	else
	{
		sprintf(src_port, "%hu", ntohs(rule->src_port));
	}

	/* Convert dst_port to string */
	if (ntohs(rule->dst_port) == 0)
	{
		sprintf(dst_port, "any");
	}
	else if (ntohs(rule->dst_port) == 1023)
	{
		sprintf(dst_port, ">1023");
	}
	else
	{
		sprintf(dst_port, "%hu", ntohs(rule->dst_port));
	}

	/* Convert ack to string */
	if (rule->ack == ACK_NO)
	{ ack = "no"; }
	else if (rule->ack == ACK_YES)
	{ ack = "yes"; }
	else
	{ ack = "any"; }

	/* Convert action to string */
	if (rule->action == NF_ACCEPT)
	{ action = "accept"; }
	else
	{ action = "drop"; }

	sprintf(rule_string, "%s %s %s %s %s %s %s %s %s", name, direction, src_ip, dst_ip, protocol, src_port, dst_port, ack, action);
	printf("%s\n", rule_string);
}

int string_to_rules(char *buffer, size_t buffer_size, char *rules, size_t *rules_size)
{
	size_t i;
	char *next_rule;
	char *next_field;
	char *next_subfield;
	size_t field_size;
	rule_t rules_array[MAX_RULES];
	size_t rules_num = 0;
	rule_t rule_struct;
	struct in_addr ip_address;

	next_rule = strtok(buffer, "\r\n");
	*rules_size = 0;

	while (next_rule != NULL)
	{
		/* Parse each rule field in the string into a struct field */

		/* Parse rule_name field */
		next_field = strsep(&next_rule, " ");
		if (next_rule == NULL) { return -1; }
		field_size = (next_rule  - next_field);
		memcpy(rule_struct.rule_name, next_field, field_size);

		/* Parse direction field */
		next_field = strsep(&next_rule, " ");
		if (next_rule == NULL) { return -1; }
		if (strcmp(next_field, "in") == 0)
		{ rule_struct.direction = DIRECTION_IN; }
		else if (strcmp(next_field, "out") == 0)
		{ rule_struct.direction = DIRECTION_OUT; }
		else if (strcmp(next_field, "any") == 0)
		{ rule_struct.direction = DIRECTION_ANY; }
		else
		{ return -1; }
		
		/* Parse src_ip, src_prefix_mask, src_prefix_size fields */
		next_field = strsep(&next_rule, " ");
		if (next_rule == NULL) { return -1; }
		if (strcmp(next_field, "any") == 0)
		{
			rule_struct.src_ip = 0;
			rule_struct.src_prefix_mask = 0;
			rule_struct.src_prefix_size = 0;
		}
		else
		{
			next_subfield = strsep(&next_field, "/");
			if (next_field == NULL) {return -1; }
			inet_pton(AF_INET, next_subfield, &ip_address); /* Convert IPv4 address from text to binary form */
			rule_struct.src_ip = ip_address.s_addr;
			rule_struct.src_prefix_size = atoi(next_field);
			rule_struct.src_prefix_mask = cidr_to_mask(rule_struct.src_prefix_size);
		}
		
		/* Parse dst_ip, dst_prefix_mask, dst_prefix_size fields */
		next_field = strsep(&next_rule, " ");
		if (next_rule == NULL) { return -1; }
		if (strcmp(next_field, "any") == 0)
		{
			rule_struct.dst_ip = 0;
			rule_struct.dst_prefix_mask = 0;
			rule_struct.dst_prefix_size = 0;
		}
		else
		{
			next_subfield = strsep(&next_field, "/");
			if (next_field == NULL) {return -1; }
			inet_pton(AF_INET, next_subfield, &ip_address); /* Convert IPv4 address from text to binary form */
			rule_struct.dst_ip = ip_address.s_addr;
			rule_struct.dst_prefix_size = atoi(next_field);
			rule_struct.dst_prefix_mask = cidr_to_mask(rule_struct.src_prefix_size);
		}

		/* Parse protocol field */
		next_field = strsep(&next_rule, " ");
		if (next_rule == NULL) { return -1; }
		if (strcmp(next_field, "ICMP") == 0)
		{ rule_struct.protocol = PROT_ICMP; }
		else if (strcmp(next_field, "TCP") == 0)
		{ rule_struct.protocol = PROT_TCP; }
		else if (strcmp(next_field, "UDP") == 0)
		{ rule_struct.protocol = PROT_UDP; }
		else if (strcmp(next_field, "any") == 0)
		{ rule_struct.protocol = PROT_ANY; }
		else
		{ return -1; }

		/* Parse src_port field */
		next_field = strsep(&next_rule, " ");
		if (next_rule == NULL) { return -1; }
		if (strcmp(next_field, ">1023") == 0)
		{ rule_struct.src_port = htons(1023); }
		else
		{ rule_struct.src_port = htons(atoi(next_field)); }

		/* Parse dst_port field */
		next_field = strsep(&next_rule, " ");
		if (next_rule == NULL) { return -1; }
		if (strcmp(next_field, ">1023") == 0)
		{ rule_struct.dst_port = htons(1023); }
		else
		{ rule_struct.dst_port = htons(atoi(next_field)); }

		/* Parse ack field */
		next_field = strsep(&next_rule, " ");
		if (next_rule == NULL) { return -1; }
		if (strcmp(next_field, "no") == 0)
		{ rule_struct.ack = ACK_NO; }
		else if (strcmp(next_field, "yes") == 0)
		{ rule_struct.ack = ACK_YES; }
		else if (strcmp(next_field, "any") == 0)
		{ rule_struct.ack = ACK_ANY; }
		else
		{ return -1; }
		
		/* Parse action field */
		next_field = strsep(&next_rule, " ");
		if (strcmp(next_field, "accept") == 0)
		{ rule_struct.action = NF_ACCEPT; }
		else if (strcmp(next_field, "drop") == 0)
		{ rule_struct.action = NF_DROP; }
		else
		{ return -1; }

		rules_array[rules_num] = rule_struct;
		++rules_num;

		next_rule = strtok(NULL, "\r\n");
	} 
	for (i=0; i<rules_num; ++i)
	{
		memcpy((rules + (i * sizeof(rule_t))), &rules_array[i], sizeof(rule_t));
		*rules_size += sizeof(rule_t);
	}
	return 0;
}

static unsigned int cidr_to_mask(unsigned int cidr)
{
	unsigned int mask = 0;
	int i;
	
	for (i=0; i<32; ++i)
	{
		if (i < cidr)
		{
			mask = mask | 1;
		}
		mask = mask << 1;
	}
	return htonl(mask);
}


