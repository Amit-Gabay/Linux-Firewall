obj-m += firewall.o
firewall-objs := core.o rules_table.o log.o connections.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
