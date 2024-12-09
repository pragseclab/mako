from probes.probe import Probe
import nmap
import socket
import logging
import concurrent.futures

class NMAPProbe(Probe):

    def __init__(self, domain, ip):
        self.ports = [line.strip() for line in open("config/ports.csv", "r").readlines()]
        super().__init__(domain, ip)

    def run(self):
        # Custom banner-grab
        with concurrent.futures.ThreadPoolExecutor() as executor: 
            futures = executor.map(self.banner_grab, self.ports)
        results = {port: result for (port, result) in zip(self.ports, futures)}
        return results

    def banner_grab(self, port):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        try:
            s.connect((self.ip, int(port)))
            s.send(b"WhoAreYou\r\n\r\n")
            banner_raw = s.recv(4096)
            banner = banner_raw.decode("utf-8")
            s.close()
            return banner
        except socket.timeout as e:
            return 408
        except socket.error as e:
            return e.errno
        except UnicodeDecodeError as e:
            return str(banner_raw)
        except Exception as e:
            logging.error(str(e))
            return None
