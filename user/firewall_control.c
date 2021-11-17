#include "serialization.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <assert.h>

int show_rules();
int load_rules(char *file_path);
int show_log();
int clear_log();

static const char *RULES_PATH = "/sys/class/Firewall_Class/Firewall_Device/rules";
static const char *RESET_PATH = "/sys/class/Firewall_Class/Firewall_Device/reset";
static const char *LOG_PATH   = "/dev/Firewall_Device";
static size_t PAGE_SIZE;

int main(int argc, char *argv[])
{	
	int status;
	assert(argc ==  2 || argc == 3);
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
		else
		{
			fprintf(stderr, "Invalid firewall command!");
			return 1;
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
			fprintf(stderr, "Invalid firewall command!");
			return 1;
		}
	}
	
	if (status < 0)
	{
		perror("An error has occurred");
		return -1;
	}
	return 0;
}

int show_rules()
{
	char *buffer = (char *) malloc(PAGE_SIZE * sizeof(char));
	size_t data_size;
	int rules_attr_fd = open(RULES_PATH, O_RDONLY);
	if (rules_attr_fd == -1)
	{
		return -1;
	}
	data_size = read(rules_attr_fd, buffer, PAGE_SIZE);
	if (close(rules_attr_fd) == -1)
	{
		return -1;
	}
	print_rules(buffer, data_size);
	free(buffer);
	return 0;
}

int load_rules(char *file_path)
{
	char *buffer = (char *) malloc(PAGE_SIZE * sizeof(char));
	char *rules = (char *) malloc(MAX_RULES * sizeof(rule_t));
	size_t rules_size;
	size_t bytes_read;
	size_t bytes_written;
	int input_rules_fd;
	int output_rules_fd;
	int conversion_status;

	/* Read rules string from input file */
	input_rules_fd = open(file_path, O_RDONLY);
	if (input_rules_fd == -1)
	{
		return -1;
	}
	bytes_read = read(input_rules_fd, buffer, PAGE_SIZE);
	if (bytes_read == -1)
	{
		return -1;
	}
	if (close(input_rules_fd) == -1)
	{
		return -1;
	}
	
	/* Convert rules from textual form into structs array form */
	conversion_status = string_to_rules(buffer, bytes_read, rules, &rules_size);
	if (conversion_status == -1)
	{
		return -1;
	}

	/* Write the rules in the structs array form into the sysfs rules attribute file */
	output_rules_fd = open(RULES_PATH, O_WRONLY);
	if (output_rules_fd == -1)
	{
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
		errno = EIO;
		return -1;
	}
	return 0;
}

int show_log()
{
	log_row_t *buffer = (log_row_t *) malloc(sizeof(log_row_t));
	size_t data_size;
	int rules_attr_fd = open(LOG_PATH, O_RDONLY);

	if (rules_attr_fd == -1)
	{
		return -1;
	}

	print_log_header();

	while ((data_size = read(rules_attr_fd, buffer, sizeof(log_row_t))) > 0)
	{
		print_log_row(buffer);
	}

	if (close(rules_attr_fd) == -1)
	{
		return -1;
	}

	free(buffer);
	return 0;
}

int clear_log()
{
	int reset_file_fd = open(RESET_PATH, O_WRONLY);
	if (reset_file_fd == -1)
	{
		return -1;
	}
	if (write(reset_file_fd, "1", 2) != 1)
	{
		errno = EIO;
		return -1;
	}
	if (close(reset_file_fd) == -1)
	{
		return -1;
	}
	return 0;
}


