import socket
import threading
import struct
import sys
import re

CONNS_TABLE_PATH = "/sys/class/fw/conns/conns"
PROXY_PORT_PATH = "/sys/class/fw/proxy_config/port"
DENY_REGEX = "#include\s+|#define\s+|int\s+main|void\s+main"
IN_DEVICE_ADDR = '10.1.1.3'


class Direction:
	DIRECTION_IN = 0
	DIRECTION_OUT = 1


class SmtpProxy:
	def __init__(self, smtp_port, max_len):
		# Create a IPv4 TCP socket for listening to HTTP stream
		self.PORT = smtp_port
		self.MAX_LEN = max_len
		self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		# Make the server listening socket reusable
		self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		self.socket.bind(('0.0.0.0', self.PORT))

	def serve_forever(self):
		try:
			self.socket.listen(4)
			print("[#] SMTP proxy is listening on PORT " + str(self.PORT))
			while True:
				(client_socket, client_address) = self.socket.accept()
				client_thread = threading.Thread(target=self.handle_client, name=client_address, args=(client_socket,client_address))
				client_thread.daemon = True
				client_thread.start()

        	except KeyboardInterrupt:
            		print("[#] Closing the proxy server...")

        	finally:
            		self.socket.close()
            		sys.exit(0)

	def handle_client(self, client_socket, client_address):
		server_address = find_server_from_table(client_address)
		server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		server_socket.bind(('0.0.0.0', 0))
		generated_port = server_socket.getsockname()[1]
		set_proxy_port(generated_port, client_address, server_address)
		server_socket.connect(server_address)
		server_thread = threading.Thread(target=self.serve_server, name=server_address, args=(client_socket, server_socket))
		server_thread.daemon = True
		server_thread.start()
		self.serve_client(client_socket, server_socket)

	def serve_client(self, client_socket, server_socket):
		network_interface = client_socket.getsockname()[0]
		if network_interface == IN_DEVICE_ADDR:
			direction = Direction.DIRECTION_OUT
		else:
			direction = Direction.DIRECTION_IN	

		while True:
			command = recv_cmd(client_socket)
                        # DLP (Data Leak Prevention)
			if direction == Direction.DIRECTION_OUT and command.decode() == 'data\r\n':
				send_data(server_socket, command.encode())
				
				raw_data = recv_data(client_socket)
				data = raw_data.decode()
				leakage_found = inspect_mail_body(data)
				if leakage_found == True:
                                        print("[DLP] Data leak prevented.")
					client_socket.close()
					server_socket.close()
					sys.exit(0)
				send_data(server_socket, raw_data)
				
			else:
				send_data(server_socket, command.encode())
			if command == '':
				break

	def serve_server(self, client_socket, server_socket):
		while True:
			raw_response = server_socket.recv(1024)
			if len(raw_response) == 0:
				break
			client_socket.send(raw_response)
			
		client_socket.close()
		server_socket.close()


def recv_cmd(conn_socket):
	command_buffer = ''
	while True:
		command_buffer += conn_socket.recv(1024)
		if '\r\n' in command_buffer:
			break
	return command_buffer


def recv_data(conn_socket):
	data_buffer = ''
	while True:
		data_buffer += conn_socket.recv(1024)
		if '\r\n.\r\n' in data_buffer:
			break
	return data_buffer


def send_data(conn_socket, raw_data):
	bytes_sent = 0
	bytes_to_send = len(raw_data)
	while bytes_sent < bytes_to_send:
		bytes_sent += conn_socket.send(raw_data[bytes_sent:])


def inspect_mail_body(raw_data):
	if re.search(DENY_REGEX, raw_data) != None:
		return True
	return False


def find_server_from_table(client_address):
	conns_table_device = open(CONNS_TABLE_PATH, 'r')
	raw_data = conns_table_device.read()
	conns_table_device.close()
	struct_format = "=IHHIHH"
	struct_len = struct.calcsize(struct_format)
	rows_num = len(raw_data) / struct_len
	conns_table = [struct.unpack(struct_format, raw_data[i*struct_len:(i+1)*struct_len]) for i in range(rows_num)]
	server_ip = ""
	server_port = 0
	client_ip = ip_to_network_bytes(client_address[0])
	client_port = client_address[1]
	for row in conns_table:
        	if row[3] == client_ip and row[4] == client_port and row[1] == 25:
			server_ip = network_bytes_to_ip(row[0])
			server_port = row[1]
	return server_ip, server_port


def set_proxy_port(generated_port, client_address, server_address):
	proxy_port_device = open(PROXY_PORT_PATH, 'w')
	client_ip = str(ip_to_network_bytes(client_address[0]))
	client_port = str(client_address[1])
	server_ip = str(ip_to_network_bytes(server_address[0]))
	server_port = str(server_address[1])
	config_string = client_ip+":"+client_port+","+server_ip+":"+server_port+","+str(generated_port)
	proxy_port_device.write(config_string)
	proxy_port_device.close()


def ip_to_network_bytes(ip_address):
	return socket.htonl(struct.unpack("!I", socket.inet_aton(ip_address))[0])


def network_bytes_to_ip(network_bytes):
	return socket.inet_ntoa(struct.pack("!I", socket.ntohl(network_bytes)))


if __name__ == "__main__":
	SMTP_PORT = 250
	MAX_LEN = 1024
	smtp_proxy = SmtpProxy(SMTP_PORT, MAX_LEN)
	smtp_proxy.serve_forever()
