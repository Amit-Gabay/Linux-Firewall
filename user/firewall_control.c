#include "serialization.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

int show_rules();
int load_rules(char *file_path);
int show_log();
int clear_log();
int show_connections();

static const char *RULES_PATH = "/sys/class/fw/rules/rules";
static const char *RESET_PATH = "/sys/class/fw/log/reset";
static const char *LOG_PATH   = "/dev/fw_log";
static const char *CONNS_PATH = "/sys/class/fw/conns/conns";
static size_t PAGE_SIZE;

int main(int argc, char *argv[])
{	
	int status;
	if (argc != 2 && argc != 3)
	{
		fprintf(stderr, "[ERROR] Invalid number of arguments\n");
		return -1;
	}
	/* Keep the size of PAGE */
	PAGE_SIZE = getpagesize();

	if (argc == 2)
	{
		if (strcmp(argv[1], "show_rules") == 0)
		{
			status = show_rules();
		}
		else if (strcmp(argv[1], "show_log") == 0)
		{
			status = show_log();
		}
		else if (strcmp(argv[1], "clear_log") == 0)
		{
			status = clear_log();
		}
		else if (strcmp(argv[1], "show_conns") == 0)
		{
			status = show_connections();
		}
		else
		{
			fprintf(stderr, "[ERROR] Invalid firewall command!\n");
			return -1;
		}
	}

	else /* argc == 3 */
	{
		if (strcmp(argv[1], "load_rules") == 0)
		{
			status = load_rules(argv[2]);
		}
		else
		{
			fprintf(stderr, "[ERROR] Invalid firewall command!\n");
			return -1;
		}
	}
	
	if (status < 0)
	{
		fprintf(stderr, "[ERROR] Desired operation failed!\n");
		return -1;
	}
	return 0;
}

/**
* An userspace function to show firewall rules table
*/
int show_rules()
{
	size_t data_size;
	int rules_attr_fd;
	char *buffer = (char *) malloc(PAGE_SIZE * sizeof(char));

	if(buffer == NULL)
	{ 
		return -1;
	}
	rules_attr_fd = open(RULES_PATH, O_RDONLY);
	if (rules_attr_fd == -1)
	{
		free(buffer);
		return -1;
	}
	/* Read rules from the firewall rules file attribute */
	data_size = read(rules_attr_fd, buffer, PAGE_SIZE);
	if (close(rules_attr_fd) == -1)
	{
		free(buffer);
		return -1;
	}
	/* Print the rules to the user */
	if (print_rules(buffer, data_size) == -1)
	{
		free(buffer);
		return -1;
	}
	free(buffer);
	return 0;
}

/**
* An userspace function to load firewall rules table
*/
int load_rules(char *file_path)
{
	size_t rules_size;
	size_t bytes_read;
	size_t bytes_written;
	int input_rules_fd;
	int output_rules_fd;
	int conversion_status;
	char *buffer;
	char *rules;

	buffer = (char *) malloc(PAGE_SIZE * sizeof(char));
	rules = (char *) malloc(MAX_RULES * sizeof(rule_t));
	if (buffer == NULL || rules == NULL)
	{
		return -1;
	}

	/* Read rules string from input file */
	input_rules_fd = open(file_path, O_RDONLY);
	if (input_rules_fd == -1)
	{
		free(buffer);
		free(rules);
		return -1;
	}
	bytes_read = read(input_rules_fd, buffer, PAGE_SIZE);
	if (bytes_read == -1)
	{
		free(buffer);
		free(rules);
		return -1;
	}
	if (close(input_rules_fd) == -1)
	{
		free(buffer);
		free(rules);
		return -1;
	}
	
	/* Convert rules from textual form into structs array form */
	conversion_status = string_to_rules(buffer, bytes_read, rules, &rules_size);
	free(buffer);
	if (conversion_status == -1)
	{
		free(rules);
		return -1;
	}

	/* Write the rules in the structs array form into the sysfs rules attribute file */
	output_rules_fd = open(RULES_PATH, O_WRONLY);
	if (output_rules_fd == -1)
	{
		free(rules);
		return -1;
	}
	bytes_written = write(output_rules_fd, rules, rules_size);
	free(rules);
	if (close(output_rules_fd) == -1)
	{
		return -1;
	}
	if (bytes_written < rules_size)
	{ 
		return -1;
	}
	return 0;
}

/**
* An userspace function to show firewall packets log
*/
int show_log()
{
	size_t data_size;
	int log_attr_fd;
	log_row_t *buffer;

	buffer = (log_row_t *) malloc(sizeof(log_row_t));
	if (buffer == NULL)
	{
		return -1;
	}

	log_attr_fd = open(LOG_PATH, O_RDONLY);
	if (log_attr_fd == -1)
	{
		return -1;
	}

	print_log_header(); // Print to screen the log headers

	/* Read log entries from the kernel */
	while ((data_size = read(log_attr_fd, buffer, sizeof(log_row_t))) > 0)
	{	
		print_log_row(buffer);
	}

	if (close(log_attr_fd) == -1)
	{
		return -1;
	}
	
	free(buffer);
	return 0;
}

/**
* An userspace function to clear firewall packets log
*/
int clear_log()
{
	int reset_file_fd = open(RESET_PATH, O_WRONLY);
	if (reset_file_fd == -1)
	{
		return -1;
	}
	/* Write into the firewall log_reset attribute file '1', which is the reset signal */
	if (write(reset_file_fd, "1", 1) != 1)
	{
		return -1;
	}
	if (close(reset_file_fd) == -1)
	{
		return -1;
	}
	return 0;
}

int show_connections()
{
	int connections_fd;
	char *buffer;
	size_t data_size;

	buffer = (char *) malloc(PAGE_SIZE * sizeof(char));
	
	if(buffer == NULL)
	{ 
		return -1;
	}
	connections_fd = open(CONNS_PATH, O_RDONLY);
	if (connections_fd == -1)
	{
		free(buffer);
		return -1;
	}
	/* Read TCP connections from the connections table device */
	data_size = read(connections_fd, buffer, PAGE_SIZE);
	if (close(connections_fd) == -1)
	{
		free(buffer);
		return -1;
	}
	/* Print the connections to the user */
	print_connections(buffer, data_size);	

	free(buffer);
	return 0;
}


