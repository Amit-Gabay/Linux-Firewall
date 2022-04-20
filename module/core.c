#include "fw.h"
#include "log.h"
#include "rules_table.h"
#include "connections.h"
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Amit Gabay");
MODULE_DESCRIPTION("A stateful firewall for the linux kernel.");

#define SUCCESS 	(0)
#define FAILURE 	(-1)
#define TRUE		(1)
#define FALSE		(0)
#define IN_DEVICE_NUM 	('8')
#define OUT_DEVICE_NUM 	('9')

static int MAJOR_NUMBER;
static struct class *firewall_class = NULL;
static struct device *rules_device = NULL;
static struct device *log_device = NULL;
static struct device *connections_device = NULL;
static struct device *fw_log_device = NULL;
static struct device *proxy_config_device = NULL;
/* Rules Table array */
static rule_t RULES_TABLE[MAX_RULES]; // An array of rule_t structs
static int RULES_NUM = 0;
/* Log resizing array */
static log_t LOG;	 // The resizing array head
static char *log_buffer; // Used for showing the logs array content to the userspace
static size_t log_size;  // Used for the log_buffer
/* Connections doubly linked list */
static conns_table_t CONNECTIONS_TABLE;	// Pointer to the doubly linked list first node


/**
* A function which is called whenever the firewall log device is open()ed
*/
int open_log(struct inode *_inode, struct file *_file)
{
	log_size = LOG.occupied_num * sizeof(log_row_t); // Set the current logs array size
	log_buffer = (char *) LOG.logs_array; // Place the buffer pointer at the beggining of the logs array
	return SUCCESS;
}

/**
* An implementation of read() for the firewall log device
*/
ssize_t show_log(struct file *filp, char *user_buffer, size_t length, loff_t *offp)
{
	ssize_t size_to_copy;
	
	/* Copy to user min{log_size, length} bytes */
	if (log_size > length)
	{ size_to_copy = length; }
	else
	{ size_to_copy = log_size; }

	if (size_to_copy == 0)
	{ return 0; }

	if (copy_to_user(user_buffer, log_buffer, size_to_copy))
	{
		return -EFAULT;
	}
	/* Decrease the size left to copy, and forward the buffer pointer */
	log_size -= size_to_copy;
	log_buffer += size_to_copy;
	return size_to_copy;
}

/**
* A hook function for packets inspection in the PRE-ROUTING hook point
*/
unsigned int inspect_packet(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	char *src_device;

	src_device = state->in->name;
	/* Deduce the packets direction by the networking devices direction */
	if (src_device[5] == IN_DEVICE_NUM)
	{
		/* Packet is going OUTSIDE the local network */
		return packet_verdict(RULES_TABLE, RULES_NUM, skb, DIRECTION_OUT, &LOG, &CONNECTIONS_TABLE);
	}
	/* Else, packet is going INSIDE the local network */
	return packet_verdict(RULES_TABLE, RULES_NUM, skb, DIRECTION_IN, &LOG, &CONNECTIONS_TABLE);
}

/**
* A hook function in the LOCAL-OUT hook point.
* Usage: A function for sending FTP / HTTP / SMTP packets back from the proxy, to the packets' original destination
*/
unsigned int forge_packet(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	struct iphdr *ip_header = (struct iphdr *) skb_network_header(skb);
	struct tcphdr *tcp_header;
	conns_t *connection;
	conns_row_t* row;
	__be32 src_ip;
	__be32 dst_ip;
	__be16 src_port;
	__be16 dst_port;
	packet_t *packet;
	direction_t direction;
	int verdict = NF_ACCEPT;

	if (ip_header->protocol == PROT_TCP)
	{
		connection = CONNECTIONS_TABLE.rows;
		tcp_header = (struct tcphdr *) skb_transport_header(skb);
		src_ip = ip_header->saddr;
		dst_ip = ip_header->daddr;
		src_port = ntohs(tcp_header->source);
		dst_port = ntohs(tcp_header->dest);
		packet = (packet_t *) kmalloc(sizeof(packet_t), GFP_KERNEL);

		while(connection != NULL)
		{
			row = connection->row;
			/* From local-out to server */
			if (dst_ip == row->server_side.ip && dst_port == row->server_side.port && src_port == row->proxy_port)
			{
				ip_header->saddr = row->client_side.ip;
				correct_checksum(skb);

				direction = connection->direction;

				packet->src_ip = ip_header->saddr;
				packet->dst_ip = ip_header->daddr;
				packet->src_port = ntohs(tcp_header->source);
				packet->dst_port = ntohs(tcp_header->dest);
				packet->syn = tcp_header->syn;
				packet->ack = tcp_header->ack;
				packet->psh = tcp_header->psh;
				packet->urg = tcp_header->urg;
				packet->fin = tcp_header->fin;
				packet->rst = tcp_header->rst;

				if (packet->ack == 0 && packet->syn == 1 && packet->fin == 0 && packet->rst == 0)
				{
					reset_connection_states(CONNECTIONS_TABLE.rows, packet, direction);
				}

				else
				{
					verdict = tcp_packet_verdict(&CONNECTIONS_TABLE, packet, direction);
				}

				break;
			}
			/* From local-out to client */
			else if (dst_ip == row->client_side.ip && dst_port == row->client_side.port && ((src_port == 800 && row->server_side.port == 80) || (src_port == 210 && row->server_side.port == 21) || (src_port == 250 && row->server_side.port == 25)))
			{
				ip_header->saddr = row->server_side.ip;
				tcp_header->source = htons(row->server_side.port);
				correct_checksum(skb);
				
				if (connection->direction == DIRECTION_IN)
				{
					direction = DIRECTION_OUT;
				}
				else
				{
					direction = DIRECTION_IN;
				}

				packet->src_ip = ip_header->saddr;
				packet->dst_ip = ip_header->daddr;
				packet->src_port = ntohs(tcp_header->source);
				packet->dst_port = ntohs(tcp_header->dest);
				packet->syn = tcp_header->syn;
				packet->ack = tcp_header->ack;
				packet->psh = tcp_header->psh;
				packet->urg = tcp_header->urg;
				packet->fin = tcp_header->fin;
				packet->rst = tcp_header->rst;	

				verdict = tcp_packet_verdict(&CONNECTIONS_TABLE, packet, direction);

				break;
			}

			connection = connection->next;
		}

		kfree(packet);
	}

	return verdict;
}

/**
* An implementaion of read() for the firewall sysfs rules table device
*/
ssize_t show_rules(struct device* device, struct device_attribute *attribute, char *buffer)
{
	int i;
	size_t buffer_index = 0;
	size_t rule_size = sizeof(rule_t);

	for (i=0; i<RULES_NUM; ++i)
	{
		/* Copy next rule from rules table into the buffer at buffer_index */
		memcpy((buffer + buffer_index), &(RULES_TABLE[i]), rule_size);
		buffer_index += rule_size;
	}
	return buffer_index;
}

/**
* An implementation of write() for the firewall sysfs rules table device
*/
ssize_t load_rules(struct device *device, struct device_attribute *attribute, const char *buffer, size_t count)
{
	size_t rule_size = sizeof(rule_t);
	size_t bytes_left = count;
	size_t buffer_index = 0;
	const char *next_rule;
	int new_rules_num = 0;
	rule_t *new_rules_table;
	
	new_rules_table = (rule_t *) kmalloc(sizeof(rule_t)*MAX_RULES, GFP_KERNEL);
	if (new_rules_table == NULL)
	{ return FAILURE; }
	
	/* While there are atleast rule_size bytes left & there is enough space in the table for another rule */
	while ((rule_size <= bytes_left) && (new_rules_num < MAX_RULES))
	{
		next_rule = (buffer + buffer_index); // Extract the next rule from the buffer
		memcpy(&new_rules_table[new_rules_num], next_rule, rule_size); // Copy the next rule to the temp rules table
		bytes_left -= rule_size;
		buffer_index += rule_size;
		/* Validate that the new rule is a valid rule */
		if (is_valid_rule(&new_rules_table[new_rules_num]) == FALSE)
		{
			kfree(new_rules_table);
			return FAILURE;
		}
		++new_rules_num;
	}
	/* If there is data left to read --> the left data size < rule_size OR the rules table is full */
	if (bytes_left > 0)
	{
		kfree(new_rules_table);
		return FAILURE;
	}

	/* In case of successful loading, replace the previous rules table by the new one */
	memcpy(RULES_TABLE, new_rules_table, rule_size*new_rules_num);
	kfree(new_rules_table);
	RULES_NUM = new_rules_num;

	return count;
}

/**
* An implementation of write() fo the firewall sysfs packets log device
* Resets the log if and only if it receivces a single char of '1'
*/
ssize_t reset_log(struct device *device, struct device_attribute *attribute, const char *buffer, size_t count)
{
	char reset_sign;
	/* If received a single character, which is '1' */
	if (sscanf(buffer, "%c", &reset_sign) == 1 && reset_sign == '1' && count == 1)
	{
		if (clear_log(&LOG) == FAILURE)
		{ return FAILURE; }
	}
	return count;
}

/**
* An implementation of read() for the firewall sysfs connections table device
*/
ssize_t show_connections(struct device* device, struct device_attribute *attribute, char *buffer)
{
	conns_t *node = CONNECTIONS_TABLE.rows;
	conns_row_t *row;
	size_t buffer_index = 0;
	size_t row_size = sizeof(conns_user_t);
    	conns_user_t *row_to_user;
	int i=0;

	row_to_user = (conns_user_t *) kmalloc(sizeof(conns_user_t), GFP_KERNEL);
	if (row_to_user == NULL)
	{
		return FAILURE;
	}

	while (node != NULL)
	{
		row = node->row;
        	row_to_user->client_side = row->client_side;
        	row_to_user->server_side = row->server_side;
		memcpy((buffer + buffer_index), row_to_user, row_size);
		buffer_index += row_size;
		node = node->next;
		++i;
	}

    	kfree(row_to_user);
	return buffer_index;
}

/**
* An implementation of write() for the firewall sysfs proxy port attribute
*/
ssize_t set_port(struct device *device, struct device_attribute *attribute, const char *buffer, size_t count)
{
	__be32 client_ip;
	__be32 server_ip;
	__be16 client_port;
	__be16 server_port;
	__be16 proxy_port;

	if (sscanf(buffer, "%u:%hu,%u:%hu,%hu", &client_ip, &client_port, &server_ip, &server_port, &proxy_port) < 5)
	{
		return FAILURE;
	}

	if (set_connection_proxy_port(CONNECTIONS_TABLE.rows, client_ip, client_port, server_ip, server_port, proxy_port) == FAILURE)
	{
		return FAILURE;
	}

	return count;
}

/**
* An implementation of write() for the firewall sysfs proxy ftp attribute.
* Used for adding a new TCP connection entry for the FTP data connection created
*/
ssize_t add_data_connection(struct device *device, struct device_attribute *attribute, const char *buffer, size_t count)
{
	__be32 client_ip;
	__be32 server_ip;
	__be16 server_port;

	if (sscanf(buffer, "%u,%u:%hu", &client_ip, &server_ip, &server_port) < 3)
	{
		return FAILURE;
	}

	if (insert_data_connection_row(&CONNECTIONS_TABLE, client_ip, server_ip, server_port) == FAILURE)
	{
		return FAILURE;
	}

	return count;
}

/**
* A functions which sets the log char device permissions (The file which in /dev)
*/
static int firewall_chardev_set_permissions(struct device *dev, struct kobj_uevent_env *env)
{
	/* Set character device permissions to read only for everyone */
	add_uevent_var(env, "DEVMODE=%#o", 0444);
	return 0;
}

static struct nf_hook_ops nf_pre_routing = 
{
	.hook = inspect_packet,
	.pf = PF_INET, /* IPv4 Internet Protocol Family */
	.hooknum = 0,  /* NF_INET_PRE_ROUTING */
	.priority = NF_IP_PRI_FIRST
};

static struct nf_hook_ops nf_local_out =
{
	.hook = forge_packet,
	.pf = PF_INET, /* IPv4 Internet Protocol Family */
	.hooknum = 3, /* NF_INET_LOCAL_OUT */
	.priority = NF_IP_PRI_FIRST
};

/* Set read() and open() functions for the character device */
static struct file_operations file_ops =
{
	.owner = THIS_MODULE,
	.read = show_log,
	.open = open_log
};


/* Undefine the writing permissions restriction for the sysfs attribute files */
#undef VERIFY_OCTAL_PERMISSIONS
#define VERIFY_OCTAL_PERMISSIONS(perms) (perms)

/* Define the attribute files using macro */
static DEVICE_ATTR(rules /*attribute name*/, S_IRUGO | S_IWUGO /*R+W permissions to everyone*/, show_rules, load_rules);
static DEVICE_ATTR(reset /*attribute name*/, S_IWUGO /*W permissions to everyone*/, NULL, reset_log);
static DEVICE_ATTR(conns /*attribute name*/, S_IRUGO /*R permissions to everyone*/, show_connections, NULL);
static DEVICE_ATTR(port  /*attribute name*/, S_IWUGO /*W permissions to everyone*/, NULL, set_port);
static DEVICE_ATTR(ftp   /*attribute name*/, S_IWUGO /*W permissions to everyone*/, NULL, add_data_connection);


/************************************/
/* Module Install, Remove Functions */
/************************************/
static int __init firewall_init(void)
{
	// Register character device
	MAJOR_NUMBER = register_chrdev(0 /*Dynamic allocation*/, "firewall_device", &file_ops);
	if (MAJOR_NUMBER < 0)
	{
		return FAILURE;
	}
	
	// Create sysfs class for our firewall device
	firewall_class = class_create(THIS_MODULE, "fw");
	if (IS_ERR(firewall_class))
	{
		unregister_chrdev(MAJOR_NUMBER, "firewall_device");
		return FAILURE;
	}
	
	// Set reading permissions to char device
	firewall_class->dev_uevent = firewall_chardev_set_permissions;

	// Create sysfs device for our rules table
	rules_device = device_create(firewall_class, NULL, MKDEV(MAJOR_NUMBER, 0), NULL, "rules");
	if (IS_ERR(rules_device))
	{
		class_destroy(firewall_class);
		unregister_chrdev(MAJOR_NUMBER, "firewall_device");
		return FAILURE;
	}

	// Create sysfs device for our packets log
	log_device = device_create(firewall_class, NULL, MKDEV(MAJOR_NUMBER, 1), NULL, "log");
	if (IS_ERR(log_device))
	{
		device_destroy(firewall_class, MKDEV(MAJOR_NUMBER, 0));
		class_destroy(firewall_class);
		unregister_chrdev(MAJOR_NUMBER, "firewall_device");
		return FAILURE;
	}

	// Create sysfs device for our connections table
	connections_device = device_create(firewall_class, NULL, MKDEV(MAJOR_NUMBER, 2), NULL, "conns");
	if (IS_ERR(connections_device))
	{
		device_destroy(firewall_class, MKDEV(MAJOR_NUMBER, 1));
		device_destroy(firewall_class, MKDEV(MAJOR_NUMBER, 0));
		class_destroy(firewall_class);
		unregister_chrdev(MAJOR_NUMBER, "firewall_device");
		return FAILURE;
	}

	// Create device for our packets log
	fw_log_device = device_create(firewall_class, NULL, MKDEV(MAJOR_NUMBER, 3), NULL, "fw_log");
	if (IS_ERR(fw_log_device))
	{
		device_destroy(firewall_class, MKDEV(MAJOR_NUMBER, 2));
		device_destroy(firewall_class, MKDEV(MAJOR_NUMBER, 1));
		device_destroy(firewall_class, MKDEV(MAJOR_NUMBER, 0));
		class_destroy(firewall_class);
		unregister_chrdev(MAJOR_NUMBER, "firewall_device");
		return FAILURE;
	}

	// Create a configuration device for the proxy server to get / set its port
	proxy_config_device = device_create(firewall_class, NULL, MKDEV(MAJOR_NUMBER, 4), NULL, "proxy_config");
	if (IS_ERR(proxy_config_device))
	{
		device_destroy(firewall_class, MKDEV(MAJOR_NUMBER, 3));
		device_destroy(firewall_class, MKDEV(MAJOR_NUMBER, 2));
		device_destroy(firewall_class, MKDEV(MAJOR_NUMBER, 1));
		device_destroy(firewall_class, MKDEV(MAJOR_NUMBER, 0));
		class_destroy(firewall_class);
		unregister_chrdev(MAJOR_NUMBER, "firewall_device");
		return FAILURE;
	}
	
	// Create "rules" attribute file in the rules table device
	if (device_create_file(rules_device, (const struct device_attribute *) &dev_attr_rules.attr))
	{
        device_destroy(firewall_class, MKDEV(MAJOR_NUMBER, 4));
		device_destroy(firewall_class, MKDEV(MAJOR_NUMBER, 3));
		device_destroy(firewall_class, MKDEV(MAJOR_NUMBER, 2));
		device_destroy(firewall_class, MKDEV(MAJOR_NUMBER, 1));
		device_destroy(firewall_class, MKDEV(MAJOR_NUMBER, 0));
		class_destroy(firewall_class);
		unregister_chrdev(MAJOR_NUMBER, "firewall_device");
		return FAILURE;
	}		

	// Create "reset" attribute file in the packets log device
	if (device_create_file(log_device, (const struct device_attribute *) &dev_attr_reset.attr))
	{
		device_remove_file(rules_device, (const struct device_attribute *) &dev_attr_rules.attr);
        	device_destroy(firewall_class, MKDEV(MAJOR_NUMBER, 4));
		device_destroy(firewall_class, MKDEV(MAJOR_NUMBER, 3));		
		device_destroy(firewall_class, MKDEV(MAJOR_NUMBER, 2));
		device_destroy(firewall_class, MKDEV(MAJOR_NUMBER, 1));
		device_destroy(firewall_class, MKDEV(MAJOR_NUMBER, 0));
		class_destroy(firewall_class);
		unregister_chrdev(MAJOR_NUMBER, "firewall_device");
		return FAILURE;
	}

	// Create "conns" attribute file in the connections table device
	if (device_create_file(connections_device, (const struct device_attribute *) &dev_attr_conns.attr))
	{
		device_remove_file(log_device, (const struct device_attribute *) &dev_attr_reset.attr);
		device_remove_file(rules_device, (const struct device_attribute *) &dev_attr_rules.attr);
        	device_destroy(firewall_class, MKDEV(MAJOR_NUMBER, 4));
		device_destroy(firewall_class, MKDEV(MAJOR_NUMBER, 3));
		device_destroy(firewall_class, MKDEV(MAJOR_NUMBER, 2));
		device_destroy(firewall_class, MKDEV(MAJOR_NUMBER, 1));
		device_destroy(firewall_class, MKDEV(MAJOR_NUMBER, 0));
		class_destroy(firewall_class);
		unregister_chrdev(MAJOR_NUMBER, "firewall_device");
		return FAILURE;
	}

	// Create "port" attribute file for the proxy server (In order to set the proxy random port number)
	if (device_create_file(proxy_config_device, (const struct device_attribute *) &dev_attr_port.attr))
	{
		device_remove_file(connections_device, (const struct device_attribute *) &dev_attr_conns.attr);
		device_remove_file(log_device, (const struct device_attribute *) &dev_attr_reset.attr);
		device_remove_file(rules_device, (const struct device_attribute *) &dev_attr_rules.attr);
		device_destroy(firewall_class, MKDEV(MAJOR_NUMBER, 4));
		device_destroy(firewall_class, MKDEV(MAJOR_NUMBER, 3));
		device_destroy(firewall_class, MKDEV(MAJOR_NUMBER, 2));
		device_destroy(firewall_class, MKDEV(MAJOR_NUMBER, 1));
		device_destroy(firewall_class, MKDEV(MAJOR_NUMBER, 0));
		class_destroy(firewall_class);
		unregister_chrdev(MAJOR_NUMBER, "firewall_device");
		return FAILURE;
	}

	/* Create "ftp" attribute file for the proxy server (In order to insert a new TCP connection which is created
	* as part of the FTP 'PORT' command) */
	if (device_create_file(proxy_config_device, (const struct device_attribute *) &dev_attr_ftp.attr))
	{
		device_remove_file(proxy_config_device, (const struct device_attribute *) &dev_attr_port.attr);
		device_remove_file(connections_device, (const struct device_attribute *) &dev_attr_conns.attr);
		device_remove_file(log_device, (const struct device_attribute *) &dev_attr_reset.attr);
		device_remove_file(rules_device, (const struct device_attribute *) &dev_attr_rules.attr);
		device_destroy(firewall_class, MKDEV(MAJOR_NUMBER, 4));
		device_destroy(firewall_class, MKDEV(MAJOR_NUMBER, 3));
		device_destroy(firewall_class, MKDEV(MAJOR_NUMBER, 2));
		device_destroy(firewall_class, MKDEV(MAJOR_NUMBER, 1));
		device_destroy(firewall_class, MKDEV(MAJOR_NUMBER, 0));
		class_destroy(firewall_class);
		unregister_chrdev(MAJOR_NUMBER, "firewall_device");
		return FAILURE;
	}

	// Register firewall hook
	if (nf_register_net_hook(&init_net, &nf_pre_routing) < 0)
	{
        	device_remove_file(proxy_config_device, (const struct device_attribute *) &dev_attr_ftp.attr);
        	device_remove_file(proxy_config_device, (const struct device_attribute *) &dev_attr_port.attr);
		device_remove_file(connections_device, (const struct device_attribute *) &dev_attr_conns.attr);
		device_remove_file(log_device, (const struct device_attribute *) &dev_attr_reset.attr);
		device_remove_file(rules_device, (const struct device_attribute *) &dev_attr_rules.attr);
        	device_destroy(firewall_class, MKDEV(MAJOR_NUMBER, 4));
		device_destroy(firewall_class, MKDEV(MAJOR_NUMBER, 3));	
		device_destroy(firewall_class, MKDEV(MAJOR_NUMBER, 2));
		device_destroy(firewall_class, MKDEV(MAJOR_NUMBER, 1));
		device_destroy(firewall_class, MKDEV(MAJOR_NUMBER, 0));
		class_destroy(firewall_class);
		unregister_chrdev(MAJOR_NUMBER, "firewall_device");
		return FAILURE;
	}

	if (nf_register_net_hook(&init_net, &nf_local_out) < 0)
	{
		nf_unregister_net_hook(&init_net, &nf_pre_routing);
        	device_remove_file(proxy_config_device, (const struct device_attribute *) &dev_attr_ftp.attr);
        	device_remove_file(proxy_config_device, (const struct device_attribute *) &dev_attr_port.attr);
		device_remove_file(connections_device, (const struct device_attribute *) &dev_attr_conns.attr);
		device_remove_file(log_device, (const struct device_attribute *) &dev_attr_reset.attr);
		device_remove_file(rules_device, (const struct device_attribute *) &dev_attr_rules.attr);
        	device_destroy(firewall_class, MKDEV(MAJOR_NUMBER, 4));
		device_destroy(firewall_class, MKDEV(MAJOR_NUMBER, 3));		
		device_destroy(firewall_class, MKDEV(MAJOR_NUMBER, 2));
		device_destroy(firewall_class, MKDEV(MAJOR_NUMBER, 1));
		device_destroy(firewall_class, MKDEV(MAJOR_NUMBER, 0));
		class_destroy(firewall_class);
		unregister_chrdev(MAJOR_NUMBER, "firewall_device");
		return FAILURE;
	}

	// Initialize the resizing array for the packets log
	LOG.logs_array = (log_row_t *) kmalloc(sizeof(log_row_t)*LOG_INIT_SIZE, GFP_KERNEL);
	if (LOG.logs_array == NULL)
	{
		nf_unregister_net_hook(&init_net, &nf_local_out);
		nf_unregister_net_hook(&init_net, &nf_pre_routing);
        	device_remove_file(proxy_config_device, (const struct device_attribute *) &dev_attr_ftp.attr);
        	device_remove_file(proxy_config_device, (const struct device_attribute *) &dev_attr_port.attr);
		device_remove_file(connections_device, (const struct device_attribute *) &dev_attr_conns.attr);
		device_remove_file(log_device, (const struct device_attribute *) &dev_attr_reset.attr);
		device_remove_file(rules_device, (const struct device_attribute *) &dev_attr_rules.attr);
        	device_destroy(firewall_class, MKDEV(MAJOR_NUMBER, 4));
		device_destroy(firewall_class, MKDEV(MAJOR_NUMBER, 3));		
		device_destroy(firewall_class, MKDEV(MAJOR_NUMBER, 2));
		device_destroy(firewall_class, MKDEV(MAJOR_NUMBER, 1));
		device_destroy(firewall_class, MKDEV(MAJOR_NUMBER, 0));
		class_destroy(firewall_class);
		unregister_chrdev(MAJOR_NUMBER, "firewall_device");
		return FAILURE;
	}
	LOG.occupied_num = 0;
	LOG.allocated_num = LOG_INIT_SIZE;

	return SUCCESS;
}

static void __exit firewall_cleanup(void)
{
	kfree(LOG.logs_array);
    	nf_unregister_net_hook(&init_net, &nf_local_out);
	nf_unregister_net_hook(&init_net, &nf_pre_routing);
    	device_remove_file(proxy_config_device, (const struct device_attribute *) &dev_attr_ftp.attr);
    	device_remove_file(proxy_config_device, (const struct device_attribute *) &dev_attr_port.attr);
	device_remove_file(connections_device, (const struct device_attribute *) &dev_attr_conns.attr);
	device_remove_file(log_device, (const struct device_attribute *) &dev_attr_reset.attr);
	device_remove_file(rules_device, (const struct device_attribute *) &dev_attr_rules.attr);
    	device_destroy(firewall_class, MKDEV(MAJOR_NUMBER, 4));
	device_destroy(firewall_class, MKDEV(MAJOR_NUMBER, 3));		
	device_destroy(firewall_class, MKDEV(MAJOR_NUMBER, 2));
	device_destroy(firewall_class, MKDEV(MAJOR_NUMBER, 1));
	device_destroy(firewall_class, MKDEV(MAJOR_NUMBER, 0));
	class_destroy(firewall_class);
	unregister_chrdev(MAJOR_NUMBER, "firewall_device");
}

module_init(firewall_init);
module_exit(firewall_cleanup);
