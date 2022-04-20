#ifndef _RULES_TABLE_H_
#define _RULES_TABLE_H_

#include "fw.h"
#include <linux/kernel.h>
#include <net/tcp.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/string.h>

unsigned int packet_verdict(rule_t *rules_table, int rules_num, struct sk_buff *skb, direction_t packet_direction, log_t *log, conns_table_t *connections_table);
int is_rule_matching(packet_t *packet, rule_t *rule); 
int is_valid_rule(rule_t *rule);

void from_client_to_proxy(struct sk_buff *skb, direction_t direction, __be16 packet_dst_port);
void from_server_to_proxy(struct sk_buff *skb, direction_t direction);
void correct_checksum(struct sk_buff *skb);

#endif
