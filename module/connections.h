#ifndef _CONNECTIONS_H_
#define _CONNECTIONS_H_

#include "fw.h"

unsigned int tcp_packet_verdict(conns_table_t *connections_table, packet_t *packet, direction_t direction);
conns_t *find_packet_connection(conns_t *connections_table, packet_t *packet, direction_t direction, conns_entry_t **sender_side, conns_entry_t **receiver_side);
int change_connection_state(conns_table_t *connections_table, conns_t *connection, packet_t *packet, conns_entry_t *sender_side, conns_entry_t *receiver_side);
void delete_connection_row(conns_table_t *connections_table, conns_t *connection);
int insert_connection_row(conns_table_t *connections_table, packet_t *packet, direction_t direction);
int insert_data_connection_row(conns_table_t *connection_table, __be32 client_ip, __be32 server_ip, __be16 server_port);
int set_connection_proxy_port(conns_t *connections_table, __be32 client_ip, __be16 client_port, __be32 server_ip, __be16 server_port, __be16 proxy_port);
int reset_connection_states(conns_t *connections_table, packet_t *packet, direction_t direction);

#endif
