import random
import string

class Probe:
    def __init__(self, domain, ip):
        self.domain = domain
        self.ip = ip
        self.random = random 
        self.random.seed(self.domain)
        self.user_agent = self.get_user_agent()
        self.contact_link = "https://www3.cs.stonybrook.edu/~bkondracki/"

    def run(self):
        raise NotImplementedError("run() must be implemented with actions to execute for probe")
    
    # Read user-agent list file and pick one at random
    def get_user_agent(self):
        with open("config/uas.csv", "r") as user_agent_file:
           return self.random.choice([line.strip() for line in user_agent_file])
    
    def get_random_string(self, length):
        letters = string.ascii_lowercase
        return ''.join(self.random.choice(letters) for i in range(length))
