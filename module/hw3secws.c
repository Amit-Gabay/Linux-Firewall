#include "fw.h"
#include "log.h"
#include "rules_table.h"
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Amit Gabay");

#define SUCCESS 	(0)
#define FAILURE 	(-1)
#define TRUE		(1)
#define FALSE		(0)
#define IN_DEVICE_NUM 	('8')
#define OUT_DEVICE_NUM 	('9')

static int MAJOR_NUMBER;
static struct class *firewall_class = NULL;
static struct device *firewall_device = NULL;
/* Rules Table array */
static rule_t RULES_TABLE[MAX_RULES];
static int RULES_NUM = 0;
/* Log linked list */
static log_t LOG;
static char *log_buffer;
static size_t log_size;


int open_log(struct inode *_inode, struct file *_file)
{
	log_size = LOG.occupied_num * sizeof(log_row_t);
	log_buffer = (char *) LOG.logs_array;
	return SUCCESS;
}

ssize_t show_log(struct file *filp, char *user_buffer, size_t length, loff_t *offp)
{
	ssize_t size_to_copy;

	if (log_size > length)
	{ size_to_copy = length; }
	else
	{ size_to_copy = log_size; }
	copy_to_user(user_buffer, log_buffer, size_to_copy);
	log_size -= size_to_copy;
	log_buffer += size_to_copy;
	return SUCCESS;
}

static unsigned int inspect_packet(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	char *src_device;
	char *dst_device;
	src_device = state->in->name;
	dst_device = state->out->name;
	/* Deduce the packet's direction by the networking devices direction */
	if (src_device[5] == IN_DEVICE_NUM && dst_device[5] == OUT_DEVICE_NUM)
	{
		/* Packet is going INSIDE the local network */
		return packet_verdict(RULES_TABLE, RULES_NUM, skb, DIRECTION_IN);
	}
	/* Else, packet is going OUTSIDE the local network */
	return packet_verdict(RULES_TABLE, RULES_NUM, skb, DIRECTION_OUT);
}

ssize_t show_rules(struct device* device, struct device_attribute *attribute, char *buffer)
{
	int i;
	size_t buffer_index = 0;
	size_t rule_size = sizeof(rule_t);

	for (i=0; i<RULES_NUM; ++i)
	{
		memcpy((buffer + buffer_index), &(RULES_TABLE[i]), rule_size);
		buffer_index += rule_size;
	}
	return buffer_index;
}

ssize_t load_rules(struct device *device, struct device_attribute *attribute, const char *buffer, size_t count)
{
	size_t rule_size = sizeof(rule_t);
	size_t characters_left = count;
	size_t buffer_index = 0;
	const char *next_rule;

	RULES_NUM = 0; /* Ignore the previous rules table */
	
	while ((rule_size <= characters_left) && (RULES_NUM < MAX_RULES))
	{
		next_rule = (buffer + buffer_index);
		memcpy(&RULES_TABLE[RULES_NUM], next_rule, rule_size);
		characters_left -= rule_size;
		buffer_index += rule_size;
		if (is_valid_rule(RULES_TABLE, RULES_NUM) == FALSE)
		{
			printk(KERN_INFO "Not valid\n");
			RULES_NUM = 0;
			return FAILURE;
		}
		++RULES_NUM;
	}
	if (characters_left > 0)
	{
		return FAILURE;
	}
	return count;
}

ssize_t reset_log(struct device *device, struct device_attribute *attribute, const char *buffer, size_t count)
{
	char reset_sign;
	/* If received a single character, which is '1' */
	if (sscanf(buffer, "%c", &reset_sign) == 1 && reset_sign == '1' && count == 1)
	{
		clear_log(&LOG);
	}
	return count;
}

static int firewall_chardev_set_permissions(struct device *dev, struct kobj_uevent_env *env)
{
	/* Set character device permissions to read only for everyone */
	add_uevent_var(env, "DEVMODE=%#o", 0444);
	return 0;
}

static struct nf_hook_ops nf_forward = 
{
	.hook = inspect_packet,
	.pf = PF_INET, /* IPv4 Internet Protocol Family */
	.hooknum = 2,  /* NF_IP_FORWARD */
	.priority = NF_IP_PRI_FIRST
};

/* Set read() and open() functions for the character device */
static struct file_operations file_ops =
{
	.owner = THIS_MODULE,
	.read = show_log,
	.open = open_log
};


/* Undefine the writing permissions restriction */
#undef VERIFY_OCTAL_PERMISSIONS
#define VERIFY_OCTAL_PERMISSIONS(perms) (perms)

/* Define the attribute file using macro */
static DEVICE_ATTR(rules /*attribute name*/, S_IRUGO | S_IWUGO /*R+W permissions to everyone*/, show_rules, load_rules);
static DEVICE_ATTR(reset /*attribute name*/, S_IWUGO /*W permissions to everyone*/, NULL, reset_log);


/************************************/
/* Module Install, Remove Functions */
/************************************/
static int __init firewall_init(void)
{
	// Register character device
	MAJOR_NUMBER = register_chrdev(0 /*Dynamic allocation*/, "Firewall_Device", &file_ops);
	if (MAJOR_NUMBER < 0)
	{
		return FAILURE;
	}
	
	// Create sysfs class for our firewall device
	firewall_class = class_create(THIS_MODULE, "Firewall_Class");
	if (IS_ERR(firewall_class))
	{
		unregister_chrdev(MAJOR_NUMBER, "Firewall_Device");
		return FAILURE;
	}
	
	// Set permissions to char device
	firewall_class->dev_uevent = firewall_chardev_set_permissions;

	// Create sysfs device for our firewall
	firewall_device = device_create(firewall_class, NULL, MKDEV(MAJOR_NUMBER, 0), NULL, "Firewall_Device");
	if  (IS_ERR(firewall_device))
	{
		class_destroy(firewall_class);
		unregister_chrdev(MAJOR_NUMBER, "Firewall_Device");
		return FAILURE;
	}
	
	// Create firewall rules attribute file
	if (device_create_file(firewall_device, (const struct device_attribute *) &dev_attr_rules.attr))
	{
		device_destroy(firewall_class, MKDEV(MAJOR_NUMBER, 0));
		class_destroy(firewall_class);
		unregister_chrdev(MAJOR_NUMBER, "Firewall_Device");
		return FAILURE;
	}		

	// Create firewall log attribute file
	if (device_create_file(firewall_device, (const struct device_attribute *) &dev_attr_reset.attr))
	{
		device_remove_file(firewall_device, (const struct device_attribute *) &dev_attr_rules.attr);		
		device_destroy(firewall_class, MKDEV(MAJOR_NUMBER, 0));
		class_destroy(firewall_class);
		unregister_chrdev(MAJOR_NUMBER, "Firewall_Device");
		return FAILURE;
	}	

	// Register firewall hook
	if (nf_register_net_hook(&init_net, &nf_forward) < 0)
	{
		device_remove_file(firewall_device, (const struct device_attribute *) &dev_attr_reset.attr);
		device_remove_file(firewall_device, (const struct device_attribute *) &dev_attr_rules.attr);		
		device_destroy(firewall_class, MKDEV(MAJOR_NUMBER, 0));
		class_destroy(firewall_class);
		unregister_chrdev(MAJOR_NUMBER, "Firewall_Device");
		return FAILURE;
	}

	// Initialize the resizing array for the log
	LOG.logs_array = (log_row_t *) kmalloc(sizeof(log_row_t)*LOG_INIT_SIZE, GFP_KERNEL);

	return SUCCESS;
}

static void __exit firewall_cleanup(void)
{
	nf_unregister_net_hook(&init_net, &nf_forward);
	device_remove_file(firewall_device, (const struct device_attribute *) &dev_attr_reset.attr);
	device_remove_file(firewall_device, (const struct device_attribute *) &dev_attr_rules.attr);
	device_destroy(firewall_class, MKDEV(MAJOR_NUMBER, 0));
	class_destroy(firewall_class);
	unregister_chrdev(MAJOR_NUMBER, "Firewall_Device");
}

module_init(firewall_init);
module_exit(firewall_cleanup);
