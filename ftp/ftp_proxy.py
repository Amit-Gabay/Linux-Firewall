import socket
import threading
import struct
import sys

CONNS_TABLE_PATH = "/sys/class/fw/conns/conns"
PROXY_PORT_PATH = "/sys/class/fw/proxy_config/port"
PROXY_DATA_CONNECTION_PATH = "/sys/class/fw/proxy_config/ftp"


class FTPProxy:
	def __init__(self, ftp_port, max_len):
		self.PORT = ftp_port
		self.MAX_LEN = max_len
		# Create a new IPv4 TCP socket for listening for new connections
		self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		self.socket.bind(('0.0.0.0', self.PORT))

	def serve_forever(self):
		try:
			self.socket.listen(4)
			print("[#] FTP proxy is listening on PORT " + str(self.PORT))
			while True:
				(client_socket, client_address) = self.socket.accept()
				client_thread = threading.Thread(target=self.handle_client, name=client_address,args=(client_socket, client_address))
				client_thread.daemon = True
				client_thread.start()

		except KeyboardInterrupt:
			print("[#] Closing FTP proxy server...")

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
		generated_port = server_socket.getsockname()[1]
		set_proxy_port(generated_port, client_address, server_address)
		server_thread = threading.Thread(target=self.serve_server, name=server_address, args=(client_socket, server_socket))
		server_thread.daemon = True
		server_thread.start()
		self.serve_client(client_socket, server_socket, server_address)

	def serve_client(self, client_socket, server_socket, server_address):
		socket_file = client_socket.makefile()
		while True:
    			request = socket_file.readline()
			if request:
				index = request.find("PORT")
				if index > -1:
                    			(listening_ip, listening_port) = parse_port_args(request, index)
                    			allow_data_connection(listening_ip, listening_port, server_address[0])
                		server_socket.send(request.encode())
            		else:
                		client_socket.close()
				#server_socket.close()
				break

	def serve_server(self, client_socket, server_socket):
		while True:
            		response = server_socket.recv(self.MAX_LEN)
            		if response:
                		client_socket.send(response)
           		else:
				client_socket.close()
                		#server_socket.close()
				break


def parse_port_args(request, index):
	data = request[index+5:-2].split(",")
	ip_string = data[3] + "." + data[2] + "." + data[1] + "." + data[0]
	listening_ip = str(ip_to_network_bytes(ip_string))
	listening_port = int(data[4])*256 + int(data[5])
	return listening_ip, socket.ntohs(listening_port)


def allow_data_connection(listening_ip, listening_port, original_server_ip):
	proxy_ftp_device = open(PROXY_DATA_CONNECTION_PATH, 'w')
	client_ip = str(ip_to_network_bytes(original_server_ip))
	server_ip = str(ip_to_network_bytes(listening_ip))
	server_port = str(socket.ntohs(listening_port))
	config_string = client_ip + "," + server_ip + ":" + server_port
	proxy_ftp_device.write(config_string)
	proxy_ftp_device.close()


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
        	if row[3] == client_ip and row[4] == client_port and row[1] == 21:
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


if __name__ == '__main__':
	FTP_PORT = 210
	MAX_LEN = 1024
	ftp_proxy = FTPProxy(FTP_PORT, MAX_LEN)
	ftp_proxy.serve_forever()
