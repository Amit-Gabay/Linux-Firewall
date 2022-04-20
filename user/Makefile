all: firewall_control

firewall_control: firewall_control.c serialization.c
	gcc -Wall -o firewall_control firewall_control.c serialization.c

clean:
	rm -f firewall_control.c serialization.c firewall_control *~
