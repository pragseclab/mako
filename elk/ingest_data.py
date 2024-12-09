from elasticsearch import Elasticsearch
from multiprocessing.dummy import Pool
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
import json
import hashlib
import sys
import os

es = Elasticsearch(hosts=["http://192.168.2.47:9200", "http://192.168.2.89:9200", "http://192.168.2.90:9200",
                        "http://192.168.2.91:9200", "http://192.168.2.92:9200"])

def index_doc(path):
    path = os.path.join(sys.argv[1], path)

    try:
        name = path.split("/")[-1]

        doc_id = hashlib.md5(name[:-5].encode())
        doc_id = str(doc_id.hexdigest())

        timestamp = "-".join(name.split("-")[-3:])[:-5]
        domain = "-".join(name.split("-")[:-3])

        # Create indicies (if they don't already exist
        index_month = f"{timestamp.split('-')[0]}-{timestamp.split('-')[1]}"
        index_types = ["tls", "dns", "http", "html", "port_scan", "end_index_headers"]
        index_names = {f"{index_month}_{index_type}" : index_type for index_type in index_types}
    except Exception as e:
        print(path, str(e))
        return

    # Check if this document already exists
    if(es.exists(index=f"{index_month}_dns", id=doc_id)):
        return

    # Load data
    try:
        with open(path, "r") as f:
            data = json.load(f)
    except Exception as e:
        print(name, str(e))
        return

    # Fix the period in TLS field names
    if("tls" in data):
        data["tls"]["TLSv1_1"] = data["tls"]["TLSv1.1"]
        data["tls"]["TLSv1_2"] = data["tls"]["TLSv1.2"]
        data["tls"]["TLSv1_3"] = data["tls"]["TLSv1.3"]
        del data["tls"]["TLSv1.1"]
        del data["tls"]["TLSv1.2"]
        del data["tls"]["TLSv1.3"]

    # Change the directory listing and header entries to strings
    if("html" in data):
        response_codes_string = json.dumps(data["html"]["directory_info"]["dir_response_codes"])
        del data["html"]["directory_info"]["dir_response_codes"]
        data["html"]["directory_info"]["dir_response_codes"] = response_codes_string

        index_headers_string = json.dumps(data["html"]["index_headers"])
        del data["html"]["index_headers"]
        data["html"]["index_headers"] = index_headers_string

        error_headers_string = json.dumps(data["html"]["404_headers"])
        del data["html"]["404_headers"]
        data["html"]["404_headers"] = error_headers_string

    # Change the end index headers field to a string
    if("end_index_headers" in data):
        end_index_headers_string = json.dumps(data["end_index_headers"])
        del data["end_index_headers"]
        data["end_index_headers"] = {"headers" : end_index_headers_string}

    # Enter each field into the database
    for index_name, index_type in index_names.items():
        if("error" in data):
            ingest_data = {"error" : data["error"]}
        elif(not index_type in data):
            continue
        else:
            ingest_data = data[index_type].copy()
        ingest_data['domain'] = domain
        ingest_data['timestamp'] = timestamp

        try:
            es.index(index=index_name, id=doc_id, document=ingest_data)
        except Exception as e:
            print(name, str(e))
            continue

def index_multithreaded(files_list):
    MAX_JOBS_IN_QUEUE = 100

    with ThreadPoolExecutor(max_workers=10) as executor:
        # A dictionary which will contain a list the future info in the key, and the filename in the value
        jobs = {}

        # Loop through the files, and run the parse function for each file, sending the file-name to it.
        # The results of can come back in any order.
        files_left = len(files_list) #<----
        files_iter = iter(files_list) #<------

        while files_left:
            for this_file in files_iter:
                job = executor.submit(index_doc, os.path.join(sys.argv[1], this_file))
                jobs[job] = this_file
                if len(jobs) > MAX_JOBS_IN_QUEUE:
                    break #limit the job submission for now job

            # Get the completed jobs whenever they are done
            for job in as_completed(jobs):

                files_left -= 1 #one down - many to go...   <---

                # Send the result of the file the job is based on (jobs[job]) and the job (job.result)
                results_list = job.result()
                this_file = jobs[job]

                # delete the result from the dict as we don't need to store it.
                del jobs[job]

                try:
                    sys.stdout.write("\rFiles left: %i" % files_left)
                    sys.stdout.flush()
                except:
                    pass
                break; #give a chance to add more jobs <-----


index_multithreaded(os.listdir(sys.argv[1]))
