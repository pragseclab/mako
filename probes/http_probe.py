from http.client import HTTPResponse
from probes.probe import Probe
from probes.html_probe import HTMLProbe
from httpsocket import HTTPSocket
import concurrent.futures
import socket
import logging

class HTTPProbe(Probe):

    def run(self):
        http_one_support = self.http_one_support()
        http_method_support = self.http_method_support()
        return {
            "http_one_support" : http_one_support,
            "http_method_support" : http_method_support
        }

    def send_http_request(self, domain, ip, payload):
        s = HTTPSocket()
        try:
            s.connect(domain, ip, tls=False)
            response = s.send(payload)
            return response
        except socket.timeout as e:
            return 408
        except OSError:
            return None
        except Exception as e:
            logging.error(str(e))
            return None
        finally:
            s.close()

    def http_one_support(self):
        response = self.send_http_request(self.domain, self.ip, f"HEAD / HTTP/1.0\r\nHost: {self.domain}\r\nUser-Agent: {self.user_agent}\r\nX-Experiment: {self.contact_link}\r\n\r\n".encode())
        if(response == None or type(response) == int):
            return response
        return response.startswith("HTTP/1.0")

    def http_method_support(self):
        methods = {
            "OPTIONS" : f"OPTIONS / HTTP/1.1\r\nHost: {self.domain}\r\nUser-Agent: {self.user_agent}\r\nX-Experiment: {self.contact_link}\r\n\r\n",
            "TRACE" :  f"TRACE / HTTP/1.1\r\nHost: {self.domain}\r\nHostA: Hello\r\nUser-Agent: {self.user_agent}\r\nX-Experiment: {self.contact_link}\r\n\r\n",
            "TRACK" :  f"TRACK / HTTP/1.1\r\nHost: {self.domain}\r\nHostA: Hello\r\nUser-Agent: {self.user_agent}\r\nX-Experiment: {self.contact_link}\r\n\r\n"
        }

        with concurrent.futures.ThreadPoolExecutor(len(methods)) as executor: 
            futures = [executor.submit(self.send_http_request, self.domain, self.ip, payload.encode()) for payload in methods.values()]
        results = {method: f.result() for (method, f) in zip(methods.keys(), futures)}

        return results