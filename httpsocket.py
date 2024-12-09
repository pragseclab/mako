import socket
import ssl
from http.client import HTTPResponse, RemoteDisconnected
from io import BytesIO

class HTTPSocket:
    def __init__(self):
        self.parser = HTTPResponseParser()

    def connect(self, domain, ip, tls=False, timeout=2):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.settimeout(timeout)
        self.domain = domain
        self.ip = ip 
        self.tls = tls

        if(tls):
            context = ssl.SSLContext(protocol=ssl.PROTOCOL_TLS)
            context.verify_mode = ssl.CERT_NONE # disable cert. validation
            context.check_hostname = False  # disable host name checking
            self.socket = context.wrap_socket(self.socket, server_hostname=domain, do_handshake_on_connect=False) 
            self.socket.connect((ip, 443))
        else:
            self.socket.connect((ip, 80))

    def send(self, data, max_response_size=4096):
        self.socket.send(data)
        response_bytes = self.recv(max_response_size)

        # If a redirect message is received, convert the socket to TLS and retry
        if(self.parser.parsed_response and 
        (self.parser.parsed_response.status >= 300 and self.parser.parsed_response.status <= 308) and 
        self.parser.parsed_response.getheader("Location") and 
        self.parser.parsed_response.getheader("Location").startswith("https")):
            self.connect(self.domain, self.ip, tls=True)
            self.socket.send(data)
            response_bytes = self.recv(max_response_size)

        if(response_bytes):
            try:
                result = response_bytes.decode("utf-8")
            except UnicodeDecodeError:
                result = str(response_bytes)
        else:
            result = None
        return result

    def recv(self, max_response_size):
        response_bytes = None
        try:
            response_bytes = self.socket.recv(max_response_size)
        except socket.timeout:
            response_bytes = None
        self.parser.parse(response_bytes)
        return response_bytes

    def close(self):
        try:
            self.socket.shutdown(socket.SHUT_RDWR)
            self.socket.close()
        except socket.error:
            pass

# Fake socket used to parse raw HTTP response packets
# Taken from answer here: https://stackoverflow.com/questions/24728088/python-parse-http-response-string
class HTTPResponseParser:
    def parse(self, response_bytes):
        self.response_bytes = response_bytes
        self._file = BytesIO(response_bytes)
        self.parsed_response = HTTPResponse(self)
        try:
            self.parsed_response.begin()
        except RemoteDisconnected:
            self.parsed_response = None
    def makefile(self, *args, **kwargs):
        return self._file