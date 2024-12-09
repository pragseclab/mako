from consumer import ReconnectingConsumer
from crawler import Crawler
import pika
import json
import argparse
import logging
import os
import sys
import datetime
import certstream
import random
import signal
import threading
import functools
import regex as re

LOGGER = logging.getLogger("web_sec_audit")
LOGGER.setLevel(logging.DEBUG)

total_ct_domains = 0
total_ct_filter_domains = 0

output_dir = None

main_channel = None
main_queue = None

delay_channel = None
delay_queues = ["delay_hour", "delay_day", "delay_week"]

with open("config/domain_blocklist.csv", "r") as f:
    ct_domain_blocklist = f.readlines()

blocklist = [domain.strip().lower().replace(".", "\\.") for domain in ct_domain_blocklist]
blocklist_string = "|".join(blocklist)
p = re.compile("(?:%s)$" % (blocklist_string))

def is_blocklist_domain(domain):
    try:
        if(p.search(domain) != None):
            return True
    except:
        pass
    return False

# Callback for each domain found on CT
def push_domain(message, context):
    global total_ct_domains, total_ct_filter_domains

    if(message['message_type'] == "certificate_update"):
        all_domains = message['data']['leaf_cert']['all_domains']

        if(len(all_domains) > 0):
            for domain in all_domains:
                total_ct_domains+=1
                domain = domain.lower().strip()
                if(domain.startswith('*.')):
                    continue
                if(is_blocklist_domain(domain)):
                    continue
                total_ct_filter_domains+=1
                if(random.random() > 0.01):
                    continue
            
                main_channel.basic_publish(exchange="", routing_key=main_queue, 
                body=domain, properties=pika.BasicProperties(delivery_mode=2))
                for delay_queue in delay_queues:
                    delay_channel.basic_publish(exchange="", routing_key=delay_queue, 
                    body=domain, properties=pika.BasicProperties(delivery_mode=2))

def ack_message(ch, delivery_tag):
    if(ch.is_open):
        ch.basic_ack(delivery_tag)

def async_crawl(ch, delivery_tag, domain):
    domain = domain.decode("utf-8")
    logging.error(f"Probing site: {domain}")
    crawler = Crawler(domain)
    try:
        result = crawler.probe_site()
    except Exception as e:
        result = json.dumps({"error" : str(e)})

    timestamp = str(datetime.datetime.now().isoformat()).split(".")[0]
    with open(os.path.join(output_dir, f"{domain}-{timestamp}.json"), "w") as output_file:
        output_file.write(result)
    cb = functools.partial(ack_message, ch, delivery_tag)
    ch.connection.add_callback_threadsafe(cb)

def on_message(ch, method_frame, _header_frame, body, args):
    thrds = args
    delivery_tag = method_frame.delivery_tag
    t = threading.Thread(target=async_crawl, args=(ch, delivery_tag, body))
    t.start()
    thrds.append(t)

def process_args():
    parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter)
    action_parsers = parser.add_subparsers(help="Producer or consumer", dest="action")

    producer_parser = action_parsers.add_parser("producer")
    consumer_parser = action_parsers.add_parser("consumer")

    parser.add_argument("-q", "--queue",
                        type=str,
                        help="Name of rabbitmq queue to pull/push domains")
    parser.add_argument("-d", "--queue-host",
                        type=str,
                        help="Host to push/pull messages from")
    parser.add_argument("-p", "--queue-port",
                        type=int,
                        help="Port to push/pull messages from",
                        default=5672)

    producer_parser.add_argument("-o", "--output-dir",
                                type=str,
                                help="Location to output result files")

    consumer_parser.add_argument("-o", "--output-dir",
                                type=str,
                                help="Location to output result files")

    args = vars(parser.parse_args())

    if(args["queue"] == None or args["queue_host"] == None):
        parser.print_help()
        return None

    return args

def terminate(signal,frame):
    global total_ct_domains, total_ct_filter_domains, output_dir
    logging.error("TERMINATING")
    timestamp = str(datetime.datetime.now().isoformat()).split(".")[0]
    with open(os.path.join(output_dir, "domain_counters.csv"), "a+") as output_file:
        output_file.write(f"{timestamp},{total_ct_domains},{total_ct_filter_domains}\n")

if(__name__ == '__main__'):
    args = process_args()

    if(not args):
        sys.exit(1)

    main_queue = args["queue"]
    output_dir = args["output_dir"] if "output_dir" in args else None

    if(args["action"] == "consumer"):
        consumer = ReconnectingConsumer(args["queue_host"], args["queue_port"],
                                            username="web_sec_audit", password="web_sec_audit",
                                            output_dir=args["output_dir"])
        consumer.run()
    else:
        signal.signal(signal.SIGTERM, terminate)

        credentials = pika.PlainCredentials("web_sec_audit", "web_sec_audit")
        connection = pika.BlockingConnection(pika.ConnectionParameters(args["queue_host"], 
                                                                        args["queue_port"], 
                                                                        "/",
                                                                        credentials=credentials,
                                                                        ))
        main_channel = connection.channel()
        main_channel.confirm_delivery()
        main_channel.queue_declare(args["queue"], durable=True)
        main_channel.queue_bind(exchange="amq.direct", queue=args["queue"])

        delay_channel = connection.channel()
        delay_channel.confirm_delivery()
        delay_channel.queue_declare("delay_hour", durable=True, arguments={
            "x-message-ttl" : 60000 * 60,
            "x-dead-letter-exchange" : "amq.direct",
            "x-dead-letter-routing-key" : args["queue"]
        })
        delay_channel.queue_declare("delay_day", durable=True, arguments={
            "x-message-ttl" : 60000 * 60 * 24,
            "x-dead-letter-exchange" : "amq.direct",
            "x-dead-letter-routing-key" : args["queue"]
        })
        delay_channel.queue_declare("delay_week", durable=True, arguments={
            "x-message-ttl" : 60000 * 60 * 24 * 7,
            "x-dead-letter-exchange" : "amq.direct",
            "x-dead-letter-routing-key" : args["queue"]
        })
        certstream.listen_for_events(push_domain, url="wss://certstream.calidog.io")
