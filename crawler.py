from re import A
from probes.html_probe import HTMLProbe
from probes.dns_probe import DNSProbe
from probes.http_probe import HTTPProbe
from probes.tls_probe import TLSProbe
from probes.nmap_probe import NMAPProbe
import concurrent.futures
import multiprocessing
import threading
import logging
import signal
import argparse
import ipaddress
import json
import sys

class TimeoutException(Exception):
    def __init__(self, *args, **kwargs):
        pass

class Crawler:

    def __init__(self, domain, input_file=None, output_file=None):
        self.domain = domain
        self.output_file = output_file 
        self.input_file = input_file 

    @staticmethod
    def timeout_handler(signum, frame):
        raise TimeoutException("Timed out!")

    def ip_on_blocklist(self, ip):
        with open("config/ip_blocklist.csv", "r") as f:
            blocklist_entries = [ip.strip() for ip in f.readlines()]
        
        for entry in blocklist_entries:
            if(ip == entry):
                return True
            try:
                if(ipaddress.ip_address(ip) in ipaddress.ip_network(entry)):
                    return True
            except:
                pass
        return False

    def domain_on_blocklist(self, domain):
        with open("config/domain_blocklist.csv", "r") as f:
            blocklist_entries = [d.strip() for d in f.readlines()]
        
        for entry in blocklist_entries:
            if(domain.endswith(entry)):
                return True
        return False

    def probe_site(self, results):
        # Run the DNS features probe first to get the server IP address
        dns_features = DNSProbe(self.domain, None).run()
        results["dns"] = dns_features

        if(dns_features["ip"] != None and not self.ip_on_blocklist(dns_features["ip"])
            and not self.domain_on_blocklist(self.domain)):
            self.ip = dns_features["ip"].split(",")[0]

            html_features = HTMLProbe(self.domain, self.ip).run()
            http_features = HTTPProbe(self.domain, self.ip).run()
            tls_features = TLSProbe(self.domain, self.ip).run()
            nmap_features = NMAPProbe(self.domain, self.ip).run()
            end_index_headers = HTMLProbe(self.domain, self.ip).http_request(f"http://{self.ip}/")["headers"]

            results["html"] = html_features
            results["http"] = http_features 
            results["tls"] = tls_features
            results["port_scan"] = nmap_features
            results["end_index_headers"] = end_index_headers

        return results

def process_args():
    parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("domain",
                        nargs="?",
                        help="Host to crawl for security indicators")
    parser.add_argument("-w", "--output-file",
                        type=str,
                        help="File to write probe outputs to. This argument is required if in record mode.",
                        default=None)
    parser.add_argument("-r", "--input-file",
                        type=str,
                        help="File containing domains or IP addresses to crawl. Each line should contain only the URL.")
    args = vars(parser.parse_args())

    if(args["domain"] == None):
        parser.print_help()
        return None
    return args

if(__name__ == '__main__'):
    args = process_args()
    if(args == None):
        sys.exit(1)
    crawler = Crawler(args["domain"], input_file=args["input_file"], output_file=args["output_file"])
    results = {}
    crawler.probe_site(results)
    print(json.dumps(results))
