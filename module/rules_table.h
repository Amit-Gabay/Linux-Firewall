#ifndef _RULES_TABLE_H
#define _RULES_TABLE_H

#include "fw.h"
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/string.h>

int packet_verdict(rule_t *rules_table, int rules_num, struct sk_buff *skb, direction_t packet_direction);
int find_matching_rule(rule_t *rules_table, int rules_num, struct sk_buff *skb, direction_t direction);
int is_valid_rule(rule_t *rules_table, int rule_index);
int is_rule_matching(packet_t *packet, rule_t *rule);

#endif
