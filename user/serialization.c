#include "serialization.h"
#include <string.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

static unsigned int cidr_to_mask(unsigned int cidr);

/**
* A function which prints the rules from kernel in textual format
*/
int print_rules(char *buffer, size_t buffer_size)
{
	char *rules[MAX_RULES];
	int rules_num = 0;
	int i;
	size_t rule_size = sizeof(rule_t);
	size_t bytes_left = buffer_size;

	/* While there is another rule left in the buffer */
	while (bytes_left >= rule_size)
	{
		rules[rules_num] = (char *) malloc(rule_size);
		if (rules[rules_num] == NULL)
		{
			for (i=0; i<rules_num; ++i)
			{
				free(rules[i]);
			}
			return -1;
		}
		memcpy(rules[rules_num], buffer, rule_size);
		bytes_left -= rule_size;
		buffer += rule_size;
		++rules_num;
	}
	if (bytes_left > 0)
	{
		for (i=0; i<rules_num; ++i)
		{
			free(rules[i]);
		}
		return -1;
	}

	/* Print each rule to the user */
	for (i=0; i<rules_num; ++i)
	{
		print_single_rule((rule_t *) rules[i]);
		free(rules[i]);
	}
	return 0;
}

/**
* A function which prints a single rule to the user
*/
void print_single_rule(rule_t *rule)
{
	char rule_string[90]; // Each printed rule shouldn't take more than 90 characters
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
	else if (rule->protocol == PROT_UDP)
	{ protocol = "UDP"; }
	else
	{ protocol = "any"; }

	/* Convert src_port to string */
	if (rule->src_port == 0)
	{
		sprintf(src_port, "any");
	}
	else if (rule->src_port == 1023)
	{
		sprintf(src_port, ">1023");
	}
	else
	{
		sprintf(src_port, "%hu", rule->src_port);
	}

	/* Convert dst_port to string */
	if (rule->dst_port == 0)
	{
		sprintf(dst_port, "any");
	}
	else if (rule->dst_port == 1023)
	{
		sprintf(dst_port, ">1023");
	}
	else
	{
		sprintf(dst_port, "%hu", rule->dst_port);
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

/**
* A function which converts rules from textual form into rules array form
*/
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

	next_rule = strtok(buffer, "\n\r\n");
	*rules_size = 0;

	while (next_rule != NULL)
	{
		/* Parse each rule field in the string into a struct field */

		/* Parse rule_name field */
		next_field = strsep(&next_rule, " ");
		if (next_rule == NULL) { return -1; }
		field_size = (next_rule  - next_field);
		if (field_size > 20) { return -1; } // Rule name should be at most 20 characters long
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
			rule_struct.dst_prefix_mask = cidr_to_mask(rule_struct.dst_prefix_size);
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
		if (strcmp(next_field, "any") == 0)
		{ rule_struct.src_port = 0; }
		else if (strcmp(next_field, ">1023") == 0)
		{ rule_struct.src_port = 1023; }
		else
		{ rule_struct.src_port = atoi(next_field); }

		/* Parse dst_port field */
		next_field = strsep(&next_rule, " ");
		if (next_rule == NULL) { return -1; }
		if (strcmp(next_field, "any") == 0)
		{ rule_struct.dst_port = 0; }
		else if (strcmp(next_field, ">1023") == 0)
		{ rule_struct.dst_port = 1023; }
		else
		{ rule_struct.dst_port = atoi(next_field); }

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

		next_rule = strtok(NULL, "\n\r\n");
	} 
	for (i=0; i<rules_num; ++i)
	{
		memcpy((rules + (i * sizeof(rule_t))), &rules_array[i], sizeof(rule_t));
		*rules_size += sizeof(rule_t);
	}
	return 0;
}

/**
* A function which prints the log headers
*/
void print_log_header()
{
	printf("%-32s%-24s%-24s%-16s%-16s%-16s%s\n", "timestamp", "src_ip", "dst_ip", "src_port", "dst_port", "protocol", "action");
	printf("%-32s%s\n", "reason", "count");
}

/**
* A function which converts a single log entry from struct from into textual form, and print the resultant log entry
*/
void print_log_row(log_row_t *row)
{
	char timestamp[26];
	char src_ip[16];
	char dst_ip[16];
	char src_port[6];
	char dst_port[6];
	char *protocol;
	char *action;
	char reason[24];
	char count[11];
	struct tm *date_and_time;

	/* Convert timestamp into date & time textual form */
	date_and_time = localtime((long *) &row->timestamp);
	strftime(timestamp, 26, "%d/%m/%Y %H:%M:%S", date_and_time);
	/* Convert source & destination ip addresses from network byte order into textual form */
	inet_ntop(AF_INET, &row->src_ip, src_ip, 16);
	inet_ntop(AF_INET, &row->dst_ip, dst_ip, 16);
	/* Convert source & destination port addresses from host byte order into textual form */
	if(row->src_port == 0)
	{ sprintf(src_port, "None"); }
	else
	{ sprintf(src_port, "%hu", row->src_port); }
	if (row->dst_port == 0)
	{ sprintf(dst_port, "None"); }
	else
	{ sprintf(dst_port, "%hu", row->dst_port); }
	/* Convert protocol into textual form */
	if (row->protocol == PROT_ICMP)
	{ protocol = "icmp"; }
	else if (row->protocol == PROT_TCP)
	{ protocol = "tcp"; }
	else
	{ protocol = "udp"; }
	/* Convert action into textual form */
	if (row->action == NF_ACCEPT)
	{ action = "accept"; }
	else
	{ action = "drop"; }
	/* convert reason into textual form */
	if (row->reason == REASON_FW_INACTIVE)
	{ sprintf(reason, "%s", "REASON_FW_INACTIVE"); }
	else if (row->reason == REASON_NO_MATCHING_RULE)
	{ sprintf(reason, "%s", "REASON_NO_MATCHING_RULE"); }
	else if (row->reason == REASON_XMAS_PACKET)
	{ sprintf(reason, "%s", "REASON_XMAS_PACKET"); }
	else if (row->reason == REASON_ILLEGAL_VALUE)
	{ sprintf(reason, "%s", "REASON_ILLEGAL_VALUE"); }
	else if (row->reason == REASON_ILLEGAL_TCP_STATE)
	{ sprintf(reason, "%s", "REASON_ILLEGAL_TCP_STATE"); }
	else if (row->reason == REASON_LEGAL_TCP_STATE)
	{ sprintf(reason, "%s", "REASON_LEGAL_TCP_STATE"); }
	else if (row->reason == REASON_CANT_ADD_CONNECTION)
	{ sprintf(reason, "%s", "REASON_CANT_ADD_CONNECTION"); }
	else
	{ sprintf(reason, "%d", row->reason); }
	/* Convert count  into textual form */
	sprintf(count, "%u", row->count);

	printf("%-32s%-24s%-24s%-16s%-16s%-16s%s\n", timestamp, src_ip, dst_ip, src_port, dst_port, protocol, action);
	printf("%-32s%s\n", reason, count);
}

void print_connections(char *buffer, size_t buffer_size)
{
	size_t row_size = sizeof(conns_row_t);
	size_t rows_num = buffer_size / row_size;
	size_t buffer_index = 0;
	size_t i;
	conns_row_t *connection = (conns_row_t *) malloc(row_size);
	print_connections_header();
	
	for (i=0; i<rows_num; ++i)
	{
		memcpy(connection, (buffer + buffer_index), row_size);
		print_single_connection(connection);
		buffer_index += row_size;
	}
	
	free(connection);
}

void print_single_connection(conns_row_t *connection)
{
	char client_ip[16];
	char server_ip[16];
	char client_port[6];
	char server_port[6];
	char client_state[12];
	char server_state[12];
	state_t state;

	inet_ntop(AF_INET, &(connection->client_side.ip), client_ip, 16);
	inet_ntop(AF_INET, &(connection->server_side.ip), server_ip, 16);

	sprintf(client_port, "%hu", connection->client_side.port);
	sprintf(server_port, "%hu", connection->server_side.port);

	state = connection->client_side.state;
	if (state == SYN_SENT)
	{
		sprintf(client_state, "%s", "SYN_SENT");
	}
	else if (state == ESTABLISHED)
	{
		sprintf(client_state, "%s", "ESTABLISHED");
	}
	else if (state == FIN_WAIT_1 || state == FIN_WAIT_1_S)
	{
		sprintf(client_state, "%s", "FIN_WAIT_1");
	}
	else if (state == FIN_WAIT_2 || state == FIN_WAIT_2_S)
	{
		sprintf(client_state, "%s", "FIN_WAIT_2");
	}
	else if (state == TIME_WAIT || state == TIME_WAIT_S)
	{
		sprintf(client_state, "%s", "TIME_WAIT");
	}
	else if (state == CLOSE_WAIT || state == CLOSE_WAIT_S)
	{
		sprintf(client_state, "%s", "CLOSE_WAIT");
	}
	else if (state == CLOSED)
	{
		sprintf(client_state, "%s", "CLOSED");
	}
	else if (state == CLOSING || state == CLOSING_S)
	{
		sprintf(client_state, "%s", "CLOSING");
	}
	else // state == LAST_ACK
	{
		sprintf(client_state, "%s", "LAST_ACK");
	}

	state = connection->server_side.state;
	if (state == SYN_RCVD)
	{
		sprintf(server_state, "%s", "SYN_RCVD");
	}
	else if (state == ESTABLISHED)
	{
		sprintf(server_state, "%s", "ESTABLISHED");
	}
	else if (state == FIN_WAIT_1 || state == FIN_WAIT_1_S)
	{
		sprintf(server_state, "%s", "FIN_WAIT_1");
	}
	else if (state == FIN_WAIT_2 || state == FIN_WAIT_2_S)
	{
		sprintf(server_state, "%s", "FIN_WAIT_2");
	}
	else if (state == TIME_WAIT || state == TIME_WAIT_S)
	{
		sprintf(server_state, "%s", "TIME_WAIT");
	}
	else if (state == CLOSE_WAIT || state == CLOSE_WAIT_S)
	{
		sprintf(server_state, "%s", "CLOSE_WAIT");
	}
	else if (state == CLOSED)
	{
		sprintf(server_state, "%s", "CLOSED");
	}
	else if (state == CLOSING || state == CLOSING_S)
	{
		sprintf(server_state, "%s", "CLOSING");
	}
	else // state == LAST_ACK
	{
		sprintf(server_state, "%s", "LAST_ACK");
	}

	printf("%-16s%-16s%-16s%-16s%-16s%-16s\n", client_ip, server_ip, client_port, server_port, client_state, server_state);
}

void print_connections_header()
{
	printf("%-16s%-16s%-16s%-16s%-16s%-16s\n", "client ip", "server ip", "client port", "server port", "client state", "server state");
}


/**
* A function which converts CIDR notation into IPv4 mask address
*/
static unsigned int cidr_to_mask(unsigned int cidr)
{
	unsigned int mask = 0;
	int i;
	
	for (i=0; i<32; ++i)
	{
		mask = mask << 1;
		if (i < cidr)
		{
			mask = mask | 1;
		}
	}
	return htonl(mask);
}


