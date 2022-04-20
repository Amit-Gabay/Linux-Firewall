import socket
import threading
import struct
import sys
import re
import gzip
import cStringIO
import time

CONNS_TABLE_PATH = "/sys/class/fw/conns/conns"
PROXY_PORT_PATH = "/sys/class/fw/proxy_config/port"
DENY_REGEX = "#include\s+|#define\s+|int\s+main|void\s+main"
IN_DEVICE_ADDR = '10.1.1.3'


class Direction:
    DIRECTION_IN = 0
    DIRECTION_OUT = 1


class HttpProxy:
    def __init__(self, http_port, max_len):
        # Create a IPv4 TCP socket for listening to HTTP stream
        self.PORT = http_port
        self.MAX_LEN = max_len
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Make the server socket reusable
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind(('0.0.0.0', self.PORT))

    def serve_forever(self):
        try:
            self.socket.listen(4)
            print("[#] HTTP proxy is listening on PORT " + str(self.PORT))
            while True:
                (client_socket, client_address) = self.socket.accept()
                client_thread = threading.Thread(target=self.handle_client, name=client_address,
                                                 args=(client_socket, client_address))
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
        (raw_status, raw_headers, raw_body) = recv_msg(client_socket)
        raw_request = raw_status + raw_headers + raw_body
        request_method = raw_status.split()[0]
        # POST method:
        if request_method == "POST":
            direction = determine_direction(client_socket)

            body = raw_body.decode()
            # IPS (Intrusion Prevention System):
            if is_social_login(body) == True:
                print("[IPS] Attack was blocked.")
                client_socket.close()
                server_socket.close()
                sys.exit(0)

            send_msg(server_socket, raw_request)
        # Not a POST method:
        else:
            send_msg(server_socket, raw_request)


    def serve_server(self, client_socket, server_socket):
        try:
            direction = determine_direction(server_socket)
        except:
            sys.exit(0)
        (raw_status, raw_headers, raw_body) = recv_msg(server_socket)
        raw_response = raw_status + raw_headers + raw_body

        headers = dict_headers(raw_headers)
        # Block 'application/zip' and 'text/csv' types:
        if ('Content-Type' in headers) and (filter_content_type(headers['Content-Type']) == False):
            client_socket.close()
            server_socket.close()
            sys.exit(0)

        if (not 'Content-Encoding' in headers) or (not 'gzip' in headers['Content-Encoding']):
            body = raw_body.decode('utf-8', 'ignore')
            # DLP (Data Leak Prevention)
            if (direction == Direction.DIRECTION_OUT) and (data_leak_detection(body) == True):
                print("[DLP] Data leak prevented.")
                client_socket.close()
                server_socket.close()
                sys.exit(0)

        send_msg(client_socket, raw_response)
        client_socket.close()
        server_socket.close()


def send_msg(conn_socket, raw_msg):
    bytes_sent = 0
    bytes_to_send = len(raw_msg)
    while bytes_sent < bytes_to_send:
        bytes_sent += conn_socket.send(raw_msg[bytes_sent:])


def recv_msg(conn_socket):
    raw_chunk = conn_socket.recv(4096)
    raw_msg = raw_chunk
    while '\r\n\r\n' not in raw_chunk:
        raw_chunk = conn_socket.recv(4096)
        raw_msg += raw_chunk

    end_idx = raw_msg.find('\r\n') + 2
    raw_status = raw_msg[0:end_idx]
    start_idx = end_idx
    end_idx = raw_msg.find('\r\n\r\n') + 4
    raw_headers = raw_msg[start_idx:end_idx]
    start_idx = end_idx
    raw_body = raw_msg[start_idx:]

    headers = dict_headers(raw_headers)
    if 'Content-Length' in headers:
        body_len = int(dict_headers(raw_headers)['Content-Length'])
        left_to_read = body_len - len(raw_body)
        if left_to_read > 0:
            raw_body += conn_socket.recv(left_to_read)

    return (raw_status, raw_headers, raw_body)


def parse_msg(raw_msg):
    end_idx = raw_msg.find('\r\n') + 2
    raw_status = raw_msg[0:end_idx]
    start_idx = end_idx
    end_idx = raw_msg.find('\r\n\r\n') + 4
    raw_headers = raw_msg[start_idx:end_idx]
    start_idx = end_idx
    raw_body = raw_msg[start_idx:]
    return (raw_status, raw_headers, raw_body)


def recv_headers(socket_file):
    raw_headers = ''
    while True:
        header = socket_file.readline()
        raw_headers += header
        if len(header) == 2:
            break
    return raw_headers


def recv_body(conn_socket, body_len):
    request_body = ''
    bytes_read = 0
    body_chunk = conn_socket.recv(body_len - bytes_read)
    while len(body_chunk) > 0:
        request_body += body_chunk
        bytes_read += len(body_chunk)
        body_chunk = conn_socket.recv(body_len - bytes_read)
    return request_body


def determine_direction(conn_socket):
    network_interface = conn_socket.getsockname()[0]
    if network_interface == IN_DEVICE_ADDR:
        return Direction.DIRECTION_OUT
    else:
        return Direction.DIRECTION_IN


def dict_headers(raw_headers):
    raw_headers = raw_headers.split('\r\n')
    headers_dict = {}
    for raw_header in raw_headers:
        if len(raw_header) > 2:
            raw_header = raw_header.split(':')
            header_name = raw_header[0]
            header_content = raw_header[1].strip()
            headers_dict[header_name] = header_content
    return headers_dict


def get_body_len(header):
    if header.find("Content-Length:") != -1:
        return int(header.split()[1])
    return -1


def filter_content_type(header_content):
    for content_type in header_content:
        if content_type == "text/csv" or content_type == "application/zip":
            return False
    return True


def set_accept_encoding(header):
    if header.find("Accept-Encoding:") != -1 and header.find("gzip") != -1:
        return "Accept-Encoding: defalte"
    return header


def find_server_from_table(client_address):
    conns_table_device = open(CONNS_TABLE_PATH, 'r')
    raw_data = conns_table_device.read()
    conns_table_device.close()
    struct_format = "=IHHIHH"
    struct_len = struct.calcsize(struct_format)
    rows_num = len(raw_data) / struct_len
    conns_table = [struct.unpack(struct_format, raw_data[i * struct_len:(i + 1) * struct_len]) for i in range(rows_num)]
    server_ip = ""
    server_port = 0
    client_ip = ip_to_network_bytes(client_address[0])
    client_port = client_address[1]
    for row in conns_table:
        if row[3] == client_ip and row[4] == client_port and row[1] == 80:
            server_ip = network_bytes_to_ip(row[0])
            server_port = row[1]
    return server_ip, server_port


def data_leak_detection(response_body):
    if re.search(DENY_REGEX, response_body) != None:
        return True
    return False


def is_post(request_signature):
    if request_signature.find("POST") == 0:
        return True
    return False


def is_social_login(request_body):
    fields = request_body.split("&")
    for field in fields:
        field = field.lower()
        if (field.find("social_site") != -1) and (field.find("true") != -1):
            return True
    return False


def set_proxy_port(generated_port, client_address, server_address):
    proxy_port_device = open(PROXY_PORT_PATH, 'w')
    client_ip = str(ip_to_network_bytes(client_address[0]))
    client_port = str(client_address[1])
    server_ip = str(ip_to_network_bytes(server_address[0]))
    server_port = str(server_address[1])
    config_string = client_ip + ":" + client_port + "," + server_ip + ":" + server_port + "," + str(generated_port)
    proxy_port_device.write(config_string)
    proxy_port_device.close()


def ip_to_network_bytes(ip_address):
    return socket.htonl(struct.unpack("!I", socket.inet_aton(ip_address))[0])


def network_bytes_to_ip(network_bytes):
    return socket.inet_ntoa(struct.pack("!I", socket.ntohl(network_bytes)))


if __name__ == "__main__":
    HTTP_PORT = 800
    MAX_LEN = 1024
    http_proxy = HttpProxy(HTTP_PORT, MAX_LEN)
    http_proxy.serve_forever()
