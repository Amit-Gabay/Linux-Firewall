#ifndef _FW_H_
#define _FW_H_

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

// the protocols we will work with
typedef enum {
	PROT_ICMP	= 1,
	PROT_TCP	= 6,
	PROT_UDP	= 17,
	PROT_OTHER 	= 255,
	PROT_ANY	= 143,
} prot_t;

// various reasons to be registered in each log entry
typedef enum {
	REASON_FW_INACTIVE           = -1,
	REASON_NO_MATCHING_RULE      = -2,
	REASON_XMAS_PACKET           = -4,
	REASON_ILLEGAL_VALUE         = -6,
	REASON_ILLEGAL_TCP_STATE     = -3,
	REASON_LEGAL_TCP_STATE	     = -5,
	REASON_CANT_ADD_CONNECTION   = -7,
} reason_t;
	

// auxiliary strings, for your convenience
#define DEVICE_NAME_RULES			"rules"
#define DEVICE_NAME_LOG				"log"
#define DEVICE_NAME_CONN_TAB		"conn_tab"
#define CLASS_NAME					"fw"
#define LOOPBACK_NET_DEVICE_NAME	"lo"
#define IN_NET_DEVICE_NAME			"eth1"
#define OUT_NET_DEVICE_NAME			"eth2"

// auxiliary values, for your convenience
#define IP_VERSION		(4)
#define PORT_ANY		(0)
#define PORT_ABOVE_1023		(1023)
#define MAX_RULES		(50)
#define LOG_INIT_SIZE		(10)
#define FTP_PORT		(21)
#define HTTP_PORT		(80)
#define SMTP_PORT		(25)
#define FTP_PROXY_PORT		(210)
#define HTTP_PROXY_PORT		(800)
#define SMTP_PROXY_PORT		(250)

// device minor numbers, for your convenience
typedef enum {
	MINOR_RULES    = 0,
	MINOR_LOG      = 1,
} minor_t;

typedef enum {
	ACK_NO 		= 0x01,
	ACK_YES 	= 0x02,
	ACK_ANY 	= ACK_NO | ACK_YES,
} ack_t;

typedef enum {
	NOT_SET		= 0x00,
	SET		= 0x01,
} flag_t;

typedef enum {
	DIRECTION_IN 	= 0x01,
	DIRECTION_OUT 	= 0x02,
	DIRECTION_ANY 	= DIRECTION_IN | DIRECTION_OUT,
} direction_t;

// rule base
typedef struct {
	char rule_name[20];			// names will be no longer than 20 chars
	direction_t direction;
	__be32	src_ip;
	__be32	src_prefix_mask; 	// e.g., 255.255.255.0 as int in the local endianness
	__u8    src_prefix_size; 	// valid values: 0-32, e.g., /24 for the example above
								// (the field is redundant - easier to print)
	__be32	dst_ip;
	__be32	dst_prefix_mask; 	// as above
	__u8    dst_prefix_size; 	// as above	
	__be16	src_port; 			// number of port or 0 for any or port 1023 for any port number > 1023  
	__be16	dst_port; 			// number of port or 0 for any or port 1023 for any port number > 1023 
	__u8	protocol; 			// values from: prot_t
	ack_t	ack; 				// values from: ack_t
	__u8	action;   			// valid values: NF_ACCEPT, NF_DROP
} rule_t;

// logging
typedef struct {
	unsigned long  	timestamp;     	// time of creation/update
	unsigned char  	protocol;     	// values from: prot_t
	unsigned char  	action;       	// valid values: NF_ACCEPT, NF_DROP
	__be32   		src_ip;		  	// if you use this struct in userspace, change the type to unsigned int
	__be32			dst_ip;		  	// if you use this struct in userspace, change the type to unsigned int
	__be16 			src_port;	  	// if you use this struct in userspace, change the type to unsigned short
	__be16 			dst_port;	  	// if you use this struct in userspace, change the type to unsigned short
	reason_t     	reason;       	// rule#index, or values from: reason_t
	unsigned int   	count;        	// counts this line's hits
} log_row_t;

// log resizing array
typedef struct {
	log_row_t *logs_array;
	int allocated_num;
	int occupied_num;
} log_t;

typedef enum {
	CLOSED = 0,
	LISTEN = 1,
	SYN_SENT = 2,
	SYN_RCVD = 3,
	ESTABLISHED = 4,
	FIN_WAIT_1 = 5,
	FIN_WAIT_2 = 6,
	TIM_WAIT = 7,
	CLOSE_WAIT = 8,
	LAST_ACK = 9,
	CLOSING = 10,
	FIN_WAIT_1_S = 11,
	FIN_WAIT_2_S = 12,
	TIM_WAIT_S = 13,
	CLOSE_WAIT_S = 14,
	LAST_ACK_S = 15,
	CLOSING_S = 16
} state_t;

// Connections table entry
typedef struct {	  	
	unsigned int	ip;		 	  
	unsigned short	port;
	unsigned short	state;
} conns_entry_t;

// Connections table row
typedef struct {
	conns_entry_t server_side;  // Server to client connection entry
	conns_entry_t client_side;  // Client to server connection entry
    	__be16 proxy_port;
} conns_row_t;

// Connections table row to send to the userspace
typedef struct {
	conns_entry_t server_side;
	conns_entry_t client_side;
} conns_user_t;

// Connections table doubly linked list node
typedef struct conns_t {
	struct conns_t *next;
	struct conns_t *prev;
	conns_row_t *row;
	direction_t direction; // The direction of the first SYN packet in the TCP connection
	__u8 is_data_connection;
} conns_t;

typedef struct conns_table_t {
	conns_t *rows;
} conns_table_t;

// packet data
typedef struct {
	direction_t direction;		// packet direction (In / Out)
	__be32 src_ip;			// source ip address
	__be32 dst_ip;			// destination ip address
	__be16 src_port;		// source port
	__be16 dst_port;		// destination port
	__u8 protocol;			// transport layer protocol (ICMP / TCP / UDP)
	/* TCP flags (Initialized for TCP packets only) */
	flag_t syn;
	flag_t ack;
	flag_t rst;
	flag_t fin;
	flag_t psh;
	flag_t urg;
} packet_t;

#endif // _FW_H_
