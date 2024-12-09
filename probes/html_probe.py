from ast import parse
from codecs import ignore_errors
from email import parser
from .probe import Probe
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import concurrent.futures
import socket
import requests
import random
import string
import re
import logging
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class HTMLProbe(Probe):

    # Collect features from HTTP/HTML content
    def run(self):
        # Get website main page
        index_response = self.http_request(f"http://{self.ip}/")

        # Get non-existent page response
        non_existent_response = self.http_request(f"http://{self.ip}/{self.get_random_string(6)}")

        # Get the robots.txt
        robots_file = self.http_request(f"http://{self.ip}/robots.txt")

        # Get the sitemap
        sitemap = self.http_request(f"http://{self.ip}/sitemap.xml")

        # Check if there is directory indexing and find out which directories are accessible
        directory_info = self.get_directory_info(index_response["body"])
        
        return {
            "index_html" : index_response["body"],
            "index_response_code" : index_response["response_code"],
            "index_headers" : index_response["headers"],
            "404_html" : non_existent_response["body"],
            "404_code" : non_existent_response["response_code"],
            "404_headers" : non_existent_response["headers"],
            "directory_info" : directory_info,
            "sitemap" : sitemap["body"] if sitemap["response_code"] == 200 else None,
            "robots" : robots_file["body"] if robots_file["response_code"] == 200 else None
        }

    # Make an HTTP request to the provided URL, using the current 
    # object's user-agent
    def http_request(self, url, timeout=2, allow_redirects=True):
        request_headers = {
            "Host" : self.domain,
            "User-Agent" : self.user_agent,
            "X-Experiment" : self.contact_link
        }

        results = {
            "body" : None,
            "response_code" : None,
            "headers" : None
        }

        response = None
        # Make request to web server, handle possible errors
        with requests.Session() as s:
            try:
                response = s.get(url, 
                                headers=request_headers, 
                                allow_redirects=allow_redirects, 
                                verify=False,
                                timeout=timeout)
            except requests.exceptions.Timeout as e:
                results["response_code"] = -408
            except requests.exceptions.ConnectionError as e:
                results["response_code"] = -502
            except Exception as e:
                logging.error(str(e))
                return results

        # If there was an error in the requests, just return what we have here
        if(response == None):
            return results

        # Parse the body
        try:
            if(response.content):
                results["body"] = response.content.decode("utf-8")
        except UnicodeDecodeError as e:
            results["body"] = str(response.content)

        # Parse the response code and headers
        try:
            if(response.status_code):
                results["response_code"] = response.status_code

            if(response.headers):
                results["headers"] = dict(response.headers)
        except Exception as e:
            logging.error(str(e))

        return results

    def is_dir_listing(self, html):
        regex_strings = ["Index of /", "Go up</span", "Directory Listing For \[", "To Parent Directory"]
        if(html == None or type(html) != str):
            return None
        return any(re.search(regex_string, html) for regex_string in regex_strings)

    def get_page_url_dirs(self, html):
        dirs = set()
        try:
            soup = BeautifulSoup(html, "html.parser")
            urls = [url["href"] for url in soup.find_all(href=True) if url.has_attr("href")]

            for url in urls:
                path = ""
                if(url.startswith("/")):
                    path = url.split("?")[0]
                else:
                    parsed_url = urlparse(url)
                    if(parsed_url.netloc == self.domain):
                        path = parsed_url.path

                if(len(path.split("/")) > 2):
                    dirs.add(path.split("/")[1])
        except Exception as e:
            logging.error(str(e))
            pass
        return dirs

    # Parse out all link directories from HTML page
    def get_directory_info(self, html):
        dirs = set()

        # If there was an index page, then find the links on it
        if(html != None):
            dirs = dirs.union(self.get_page_url_dirs(html))

        # Add in common directory names from config file
        for line in open("config/directories.csv", "r").readlines():
            dirs.add(line.strip())

        # Launch each request in a thread
        with concurrent.futures.ThreadPoolExecutor() as executor: 
            futures = [executor.submit(self.http_request, f"http://{self.ip}/{dir}") for dir in dirs]
        responses = {dir: f.result() for (dir, f) in zip(dirs, futures)}

        # Check the response bodies for dir listings
        has_dir_listing = False
        for response in responses.values():
            if(self.is_dir_listing(response["body"])):
                has_dir_listing = True
                break

        dir_response_codes = {dir: response["response_code"] for (dir, response) in responses.items()}

        return {"has_dir_listing" : has_dir_listing, "dir_response_codes" : dir_response_codes}
