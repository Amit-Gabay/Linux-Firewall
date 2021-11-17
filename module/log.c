#include "log.h"
#include <linux/ktime.h>
#include <linux/slab.h>

#define ARRAY_RESIZING_FACTOR	(2)
#define TRUE			(1)
#define FALSE			(0)


void log_packet(log_t *log, packet_t *packet, reason_t reason, __u8 action)
{
	int i;
	unsigned long timestamp = ktime_get_ns();
	log_row_t *curr_log_row;
	
	for (i=0; i<(log->occupied_num); ++i)
	{
		curr_log_row = &(log->logs_array)[i];
		if (is_log_row_matching(curr_log_row, packet, reason, action) == TRUE)
		{
			curr_log_row->timestamp = timestamp;
			++(curr_log_row->count);
		}
	}
	
	/* Else: Add the packet log to the end of the log array */
	{
		/* If log array is full -> Expand its size (Multiply its size by ARRAY_RESIZING_FACTOR) */
		if (log->occupied_num == log->allocated_num)
		{
			resize_log(log, ARRAY_RESIZING_FACTOR);
		}

		curr_log_row = &(log->logs_array)[log->occupied_num];
		curr_log_row->timestamp = timestamp;
		curr_log_row->protocol = packet->protocol;
		curr_log_row->action = action;
		curr_log_row->src_ip = packet->src_ip;
		curr_log_row->dst_ip = packet->dst_ip;
		curr_log_row->src_port = packet->src_port;
		curr_log_row->dst_port = packet->dst_port;
		curr_log_row->reason = reason;
		curr_log_row->count = 1;
	}
}

int is_log_row_matching(log_row_t *log_row, packet_t *packet, reason_t packet_reason, __u8 packet_action)
{
	if (log_row->protocol != packet->protocol)
	{ return FALSE; }
	
	if (log_row->action != packet_action)
	{ return FALSE; }
	
	if (log_row->src_ip != packet->src_ip || log_row->dst_ip != packet->dst_ip)
	{ return FALSE; }
	
	if (log_row->src_port != packet->src_port || log_row->dst_port != packet->dst_port)
	{ return FALSE; }

	if (log_row->reason != packet_reason)
	{ return FALSE; }

	return TRUE;
}

void resize_log(log_t *log, int resizing_factor)
{
	int n = log->occupied_num;
	log_row_t *array = log->logs_array;
	size_t allocation_size = n*resizing_factor;

	array = (log_row_t *) krealloc(array, sizeof(log_row_t) * allocation_size, GFP_KERNEL);
	log->allocated_num += allocation_size;
}

void clear_log(log_t *log)
{
	// Free previous allocation
	kfree(log->logs_array);
	// Allocate a new empty array with size = 10
	log->logs_array = (log_row_t *) kmalloc(sizeof(log_row_t)*LOG_INIT_SIZE, GFP_KERNEL);
	log->occupied_num = 0;
	log->allocated_num = 1;
}

