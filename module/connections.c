#include "connections.h"
#include <linux/slab.h>

#define FAILURE			(-1)
#define SUCCESS			(0)
#define TRUE			(1)
#define FALSE			(0)


unsigned int tcp_packet_verdict(conns_table_t *connections_table, packet_t *packet, direction_t direction)
{
	conns_t *connection_node;
	conns_entry_t *sender_side;
	conns_entry_t *receiver_side;
	int is_legal;

	connection_node = find_packet_connection(connections_table->rows, packet, direction, &sender_side, &receiver_side);
	/* Check if no matching TCP connection found */	
	if (connection_node == NULL)
	{
		return NF_DROP; // Because the TCP packet is not a continuance of any existing TCP connection */
	}

	is_legal = change_connection_state(connections_table, connection_node, packet, sender_side, receiver_side);
	/* Check if the packet changes the connection state to a valid state */
	if (!is_legal)
	{
		return NF_DROP; // If not, the connection state shouldn't change, and we should DROP the packet */
	}
	return NF_ACCEPT; // Else, the conection state should be changed to the new state, and we should ACCEPT the packet */
}

conns_t *find_packet_connection(conns_t *connections_table, packet_t *packet, direction_t direction, conns_entry_t **sender_side, conns_entry_t **receiver_side)
{
	conns_entry_t *sender;
	conns_entry_t *receiver;
	conns_t *connection = connections_table;	

    	/* Iterate all of the rows in the connection table */
	while (connection != NULL)
	{
		/* If it's a new FTP data connection entry */
		if (connection->row->client_side.port == 0 && packet->dst_port == connection->row->server_side.port)
		{
			if (packet->src_ip == connection->row->client_side.ip && packet->dst_ip == connection->row->server_side.ip)
			{
				/* We are initializing the connection (packet is the first SYN of the connection) */
				connection->direction = packet->direction;
				connection->row->client_side.port = packet->src_port;
				*sender_side = &(connection->row->client_side);
				*receiver_side = &(connection->row->server_side);
				return connection;
			}
		}
        	/* If the direction of the packet is same as the direction of the TCP connection initialize (direction of first SYN packet) */
		if (connection->direction == direction)
		{
			sender = &(connection->row->client_side);
			receiver = &(connection->row->server_side);
		}

		else
		{
			sender = &(connection->row->server_side);
			receiver = &(connection->row->client_side);
		}

		*sender_side = sender;
		*receiver_side = receiver;

		if (sender->ip == packet->src_ip && receiver->ip == packet->dst_ip)
		{
			/* If it's a FTP / HTTP / SMTP packet from the server side to the pre-routing */
			if (packet->src_port == HTTP_PORT || packet->src_port == FTP_PORT || packet->src_port == SMTP_PORT)
			{
				if (connection->row->proxy_port == packet->dst_port && sender->port == packet->src_port)
				{
				    	return connection;
				}
			}
			/* If it's a FTP / HTTP / SMTP packet from the local-out to the server side */
			if (packet->dst_port == HTTP_PORT || packet->dst_port == FTP_PORT || packet->dst_port == SMTP_PORT)
			{
				if (connection->row->proxy_port == packet->src_port && receiver->port == packet->dst_port)
				{
					return connection;
				} 
			}
			if (sender->port == packet->src_port && receiver->port == packet->dst_port)
			{
			    	return connection;
			}
		}

		connection = connection->next;
	}

	return NULL; // No matching connection found
}

int reset_connection_states(conns_t *connections_table, packet_t *packet, direction_t direction)
{
	conns_t *connection_node;
	conns_entry_t *sender_side;
	conns_entry_t *receiver_side;

	connection_node = find_packet_connection(connections_table, packet, direction, &sender_side, &receiver_side);
	/* Check if no matching TCP connection found */	
	if (connection_node == NULL)
	{
		return FAILURE; // Because the TCP packet is not a continuance of any existing TCP connection */
	}

	connection_node->row->client_side.state = SYN_SENT;
	connection_node->row->server_side.state = SYN_RCVD;
	return SUCCESS;
}

int change_connection_state(conns_table_t *connections_table, conns_t *connection, packet_t *packet, conns_entry_t *sender_side, conns_entry_t *receiver_side)
{
	/* If RST packet was sent, close the connection immediately */
	if (packet->rst == 1)
	{
		/* Close connection */
		delete_connection_row(connections_table, connection);
		return TRUE;
	}

	/* An initial state before any SYN packet sent, used for creating new FTP data connections */
	if (sender_side->state == CLOSED && receiver_side->state == LISTEN)
	{
		/* Make sure that the packet is a SYN packet before accepting the packet and changing the state */
		if (packet->syn == 1 && packet->ack == 0 && packet->fin == 0 && packet->rst == 0)
		{
			sender_side->state = SYN_SENT;
			receiver_side->state = SYN_RCVD;
			return TRUE;
		}
		return FALSE;
	}
	
	/* Support SYN packet retransmission */
	if (sender_side->state == SYN_SENT && receiver_side->state == SYN_RCVD)
	{
		/* If a SYN packet sent again, accept it */
		if (packet->syn == 1 && packet->ack == 0 && packet->fin == 0 && packet->rst == 0)
		{
			return TRUE;
		}
	}

	if (sender_side->state == SYN_RCVD && receiver_side->state == SYN_SENT)
	{
		/* If sender sends SYN+ACK as a response to the SYN */
		if (packet->syn == 1 && packet->ack == 1 && packet->fin == 0 && packet->rst == 0)
		{
			receiver_side->state = ESTABLISHED;
			return TRUE;
		}
		/* There's no another possible state transition */
		return FALSE;
	}

	/* Support SYN+ACK packet retransmission */
	if (sender_side->state == SYN_RCVD && receiver_side->state == ESTABLISHED)
	{
		/* If a SYN+ACK packet sent again, accept it */
		if (packet->syn == 1 && packet->ack == 1 && packet->fin == 0 && packet->rst == 0)
		{
			return TRUE;
		}
	}

	if (sender_side->state == ESTABLISHED && receiver_side->state == SYN_RCVD)
	{
		if (packet->syn == 0 && packet->ack == 1 && packet->fin == 0 && packet->rst == 0)
		{
			receiver_side->state = ESTABLISHED;
			return TRUE;
		}
		return FALSE;
	}

	if (sender_side->state == SYN_RCVD && receiver_side->state == ESTABLISHED)
	{
		if (packet->syn == 0 && packet->ack == 1 && packet->fin == 1 && packet->rst == 0)
		{
			sender_side->state = FIN_WAIT_1;
			return TRUE;
		}
	}	

	if (sender_side->state == ESTABLISHED && receiver_side->state == ESTABLISHED)
	{
		if (packet->syn == 0 && packet->ack == 1 && packet->fin == 0 && packet->rst == 0)
		{
			/* Data transfer state - Keep the state as is */
			return TRUE;
		}

		if (packet->syn == 0 && packet->ack == 1 && packet->fin == 1 && packet->rst == 0)
		{

			sender_side->state = FIN_WAIT_1;
			return TRUE;
		}
		return FALSE;
	}

	/* Support first FIN+ACK packet retransmission */
	if (sender_side->state == FIN_WAIT_1 && receiver_side->state == ESTABLISHED)
	{
		/* If the first FIN+ACK sent again, accept it */
		if (packet->syn == 0 && packet->ack == 1 && packet->fin == 1 && packet->rst == 0)
		{
			/* Accept retransmission */
			return TRUE;
		}
	}

	if (sender_side->state == ESTABLISHED && receiver_side->state == FIN_WAIT_1)
	{
		if (packet->syn == 0 && packet->ack == 1 && packet->fin == 1 && packet->rst == 0)
		{
			sender_side->state = LAST_ACK;
			receiver_side->state = TIM_WAIT;
			return TRUE;
		}

		if (packet->syn == 0 && packet->ack == 1 && packet->fin == 0 && packet->rst == 0)
		{
			sender_side->state = CLOSE_WAIT;
			receiver_side->state = FIN_WAIT_2;
			return TRUE;
		}
		return FALSE;
	}

	if (sender_side->state == TIM_WAIT && receiver_side->state == LAST_ACK)
	{
		if (packet->syn == 0 && packet->ack == 1 && packet->fin == 0 && packet->rst == 0)
		{
			sender_side->state = CLOSED;
			receiver_side->state = CLOSED;
			return TRUE;
		}
		return FALSE;
	}

	if (sender_side->state == CLOSE_WAIT && receiver_side->state == FIN_WAIT_2)
	{
		if (packet->syn == 0 && packet->ack == 1 && packet->fin == 1 && packet->rst == 0)
		{
			sender_side->state = CLOSED;
			receiver_side->state = CLOSED;
			return TRUE;
		}
		return FALSE;
	}


	/* Second stage connection closure */
	if (sender_side->state == CLOSED && receiver_side->state == CLOSED)
	{
		if (packet->syn == 0 && packet->ack == 1 && packet->fin == 1 && packet->rst == 0)
		{
			sender_side->state = FIN_WAIT_1_S;
			return TRUE;
		}
		return FALSE;
	}

	/* Support first FIN+ACK packet retransmission */
	if (sender_side->state == FIN_WAIT_1_S && receiver_side->state == CLOSED)
	{
		/* If the first FIN+ACK sent again, accept it */
		if (packet->syn == 0 && packet->ack == 1 && packet->fin == 1 && packet->rst == 0)
		{
			/* Accept retransmission */
			return TRUE;
		}
	}

	if (sender_side->state == CLOSED && receiver_side->state == FIN_WAIT_1_S)
	{
		if (packet->syn == 0 && packet->ack == 1 && packet->fin == 1 && packet->rst == 0)
		{
			sender_side->state = LAST_ACK_S;
			receiver_side->state = TIM_WAIT_S;
			return TRUE;
		}

		if (packet->syn == 0 && packet->ack == 1 && packet->fin == 0 && packet->rst == 0)
		{
			sender_side->state = CLOSE_WAIT_S;
			receiver_side->state = FIN_WAIT_2_S;
			return TRUE;
		}
		return FALSE;
	}

	if (sender_side->state == TIM_WAIT_S && receiver_side->state == LAST_ACK_S)
	{
		if (packet->syn == 0 && packet->ack == 1 && packet->fin == 0 && packet->rst == 0)
		{
			delete_connection_row(connections_table, connection);
			return TRUE;
		}
		return FALSE;
	}

	if (sender_side->state == CLOSE_WAIT_S && receiver_side->state == FIN_WAIT_2_S)
	{
		if (packet->syn == 0 && packet->ack == 1 && packet->fin == 1 && packet->rst == 0)
		{
			delete_connection_row(connections_table, connection);
			return TRUE;
		}
		return FALSE;
	}

	return FALSE;
}

void delete_connection_row(conns_table_t *connections_table, conns_t *connection)
{
	if (connection->prev == NULL) // If the connection is the first node in the linked list
	{
		connections_table->rows = connection->next;
	}

	else if (connection->next == NULL) // If connection is the last node and isn't the first
	{
		connection->prev->next = NULL;
	}
	
	else // Connection isn't either the first and the last
	{
		connection->prev->next = connection->next;
		connection->next->prev = connection->prev;
	}

	kfree(connection->row);
	kfree(connection);
}

int insert_data_connection_row(conns_table_t *connections_table, __be32 client_ip, __be32 server_ip, __be16 server_port)
{
	conns_t *new_node;
	conns_row_t *new_row;

	new_node = (conns_t *) kmalloc(sizeof(conns_t), GFP_KERNEL);
	if (new_node == NULL)
	{ return FAILURE; }

	new_row = (conns_row_t *) kmalloc(sizeof(conns_row_t), GFP_KERNEL);
	if (new_row == NULL)
	{ return FAILURE; }

	memset(new_node, 0, sizeof(conns_t));
	memset(new_row, 0, sizeof(conns_row_t));

	new_row->client_side.ip = client_ip;
	new_row->client_side.port = 0; // The client_side port isn't known yet
	new_row->client_side.state = CLOSED;
	new_row->server_side.ip = server_ip;
	new_row->server_side.port = server_port;
	new_row->server_side.state = LISTEN;

	printk("NEW %hu\n", server_port);

	new_node->row = new_row;
	new_node->next = connections_table->rows;
	new_node->prev = NULL;
	new_node->is_data_connection = 1;
	if (connections_table->rows != NULL)
	{
		(connections_table->rows)->prev = new_node;
	}
	connections_table->rows = new_node;

	return SUCCESS;
}

int insert_connection_row(conns_table_t *connections_table, packet_t *packet, direction_t direction)
{
	conns_entry_t *dst_entity;
	conns_entry_t *src_entity;
	conns_t *new_node;
	conns_row_t *new_row;

	new_node = (conns_t *) kmalloc(sizeof(conns_t), GFP_KERNEL);
	if (new_node == NULL)
	{ return FAILURE; }

	new_row = (conns_row_t *) kmalloc(sizeof(conns_row_t), GFP_KERNEL);
	if (new_row == NULL)
	{ return FAILURE; }

	memset(new_node, 0, sizeof(conns_t));
	memset(new_row, 0, sizeof(conns_row_t));

	src_entity = &(new_row->client_side);
	dst_entity = &(new_row->server_side);

	src_entity->ip = packet->src_ip;
	src_entity->port = packet->src_port;
	src_entity->state = SYN_SENT;

	dst_entity->ip = packet->dst_ip;
	dst_entity->port = packet->dst_port;
	dst_entity->state = SYN_RCVD;

	//printk("NEW src_port=%hu, dst_port=%hu\n", packet->src_port, packet->dst_port);

	new_node->direction = direction;

	/* Insert the new row into the head of the rows list in the connections tble */
	new_node->row = new_row;
	new_node->next = connections_table->rows;
	new_node->prev = NULL;	
	new_node->is_data_connection = 0;
	if (connections_table->rows != NULL)
	{
		(connections_table->rows)->prev = new_node;
	}
	connections_table->rows = new_node;

	return SUCCESS;
}

int set_connection_proxy_port(conns_t *connections_table, __be32 client_ip, __be16 client_port, __be32 server_ip, __be16 server_port, __be16 proxy_port)
{
	conns_t *connection = connections_table;
	while (connection != NULL)
	{
		if (connection->row->client_side.ip == client_ip && connection->row->client_side.port == client_port)
		{
			if (connection->row->server_side.ip == server_ip && connection->row->server_side.port == server_port)
			{
				connection->row->proxy_port = proxy_port;
				return SUCCESS;
			}
		}

		connection = connection->next;
	}
	return FAILURE;
}
