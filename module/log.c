#include "log.h"
#include <linux/time.h>
#include <linux/slab.h>

#define ARRAY_RESIZING_FACTOR	(2)
#define FAILURE			(-1)
#define SUCCESS			(0)
#define TRUE			(1)
#define FALSE			(0)

/**
* A function which logs a packet
*/
void log_packet(log_t *log, packet_t *packet, reason_t reason, __u8 action)
{
	int i;
	unsigned long timestamp;
	struct timeval time;
	log_row_t *curr_log_row;
	int is_row_found = 0;

	/* Get current time in seconds since epoch (1/1/1970) */
	do_gettimeofday(&time);
	timestamp = time.tv_sec;
	
	/* Search for a matching log entry for the packet */
	for (i=0; i<(log->occupied_num); ++i)
	{
		curr_log_row = &(log->logs_array)[i];
		if (is_log_row_matching(curr_log_row, packet, reason, action) == TRUE)
		{
			/* Update the timestamp & increase the counter in the matching log entry */
			curr_log_row->timestamp = timestamp;
			++(curr_log_row->count);
			is_row_found = 1;
		}
	}
	
	/* If a matching log entry wasn't found: Add the packet log to the end of the logs array */
	if (!is_row_found)
	{
		/* If log array is full --> Expand its size (Multiply its size by ARRAY_RESIZING_FACTOR) */
		if (log->occupied_num == log->allocated_num)
		{
			if(resize_log(log, ARRAY_RESIZING_FACTOR) == FAILURE)
			{ return; }
		}
		
		/* Insert a new log row to the logs array */
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
		/* Increase occupied_num */
		++(log->occupied_num);
	}
}

/**
* A function which checks if our packet matches the given log entry
*/
int is_log_row_matching(log_row_t *log_row, packet_t *packet, reason_t packet_reason, __u8 packet_action)
{
	if (log_row->protocol != packet->protocol)
	{ return FALSE; /* There's no match */ }
	
	if (log_row->action != packet_action)
	{ return FALSE; }
	
	if (log_row->src_ip != packet->src_ip || log_row->dst_ip != packet->dst_ip)
	{ return FALSE; }
	
	if (log_row->src_port != packet->src_port || log_row->dst_port != packet->dst_port)
	{ return FALSE; }

	if (log_row->reason != packet_reason)
	{ return FALSE; }

	return TRUE; /* Found a match */
}

/**
* A function to resize the logs array when it's full
* Resizing its size by to be {resizing_factor} times bigger
*/
int resize_log(log_t *log, int resizing_factor)
{
	int n = log->occupied_num;
	size_t allocation_size = n*(resizing_factor);
	log_row_t *resized_array;

	/* Reallocate a new array {resizing_factor} times bigger than the original array */
	resized_array = (log_row_t *) krealloc(log->logs_array, sizeof(log_row_t) * allocation_size, GFP_KERNEL);
	if (resized_array == NULL)
	{ return FAILURE; }
	log->logs_array = resized_array;
	log->allocated_num += allocation_size;
	return SUCCESS;
}

/**
* A function which clears the packets log
*/
int clear_log(log_t *log)
{
	log_row_t *initialized_array;

	/* Allocate a new empty array with size = 10 */
	initialized_array = (log_row_t *) kmalloc(sizeof(log_row_t)*LOG_INIT_SIZE, GFP_KERNEL);
	if (initialized_array == NULL)
	{ return FAILURE; }
	/* Free the previous logs array */
	kfree(log->logs_array);
	log->logs_array = initialized_array;
	log->occupied_num = 0;
	log->allocated_num = LOG_INIT_SIZE;
	return SUCCESS;
}

