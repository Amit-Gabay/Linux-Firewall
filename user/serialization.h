#ifndef _SERIALIZATION_H_
#define _SERIALIZATION_H_

#include <stdint.h>
#include <stddef.h>

#define MAX_RULES		(50)

typedef enum {
	REASON_FW_INACTIVE           = -1,
	REASON_NO_MATCHING_RULE      = -2,
	REASON_XMAS_PACKET           = -4,
	REASON_ILLEGAL_VALUE         = -6,
} reason_t;

typedef enum {
	DIRECTION_IN 	= 0x01,
	DIRECTION_OUT 	= 0x02,
	DIRECTION_ANY 	= DIRECTION_IN | DIRECTION_OUT,
} direction_t;

// the protocols we will work with
typedef enum {
	PROT_ICMP	= 1,
	PROT_TCP	= 6,
	PROT_UDP	= 17,
	PROT_OTHER 	= 255,
	PROT_ANY	= 143,
} prot_t;

typedef enum {
	ACK_NO 		= 0x01,
	ACK_YES 	= 0x02,
	ACK_ANY 	= ACK_NO | ACK_YES,
} ack_t;

// rule base
typedef struct {
	char rule_name[20];			// names will be no longer than 20 chars
	direction_t direction;
	unsigned int	src_ip;
	unsigned int	src_prefix_mask; 	// e.g., 255.255.255.0 as int in the local endianness
	uint8_t    src_prefix_size; 			// valid values: 0-32, e.g., /24 for the example above
						// (the field is redundant - easier to print)
	unsigned int	dst_ip;
	unsigned int	dst_prefix_mask; 	// as above
	uint8_t   dst_prefix_size; 			// as above	
	unsigned short	src_port; 		// number of port or 0 for any or port 1023 for any port number > 1023  
	unsigned short	dst_port; 		// number of port or 0 for any or port 1023 for any port number > 1023 
	uint8_t	protocol; 			// values from: prot_t
	ack_t	ack; 				// values from: ack_t
	uint8_t	action;   			// valid values: NF_ACCEPT, NF_DROP
} rule_t;

// logging
typedef struct {
	unsigned long  	timestamp;     	// time of creation/update
	unsigned char  	protocol;     	// values from: prot_t
	unsigned char  	action;       	// valid values: NF_ACCEPT, NF_DROP
	unsigned int   	src_ip;		// if you use this struct in userspace, change the type to unsigned int
	unsigned int	dst_ip;		// if you use this struct in userspace, change the type to unsigned int
	unsigned short	src_port;	// if you use this struct in userspace, change the type to unsigned short
	unsigned short	dst_port;	// if you use this struct in userspace, change the type to unsigned short
	reason_t     	reason;       	// rule#index, or values from: reason_t
	unsigned int   	count;        	// counts this line's hits
} log_row_t;

int print_rules(char *buffer, size_t buffer_size);
void print_single_rule(rule_t *rule);
int string_to_rules(char *buffer, size_t buffer_size, char *rules, size_t *rules_size);
void print_log_row(log_row_t *log_row);
void print_log_header();

#endif // _SERIALIZATION_H_
