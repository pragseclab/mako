from .probe import Probe
import dns.resolver

class DNSProbe(Probe):
    def run(self):
        # Get A records of domain
        try:
            answers = dns.resolver.query(self.domain, "A")
            ip = ','.join([answer.to_text() for answer in answers])
        except:
            ip = None

        # Get CAA records of domain
        try:
            answers = dns.resolver.query(self.domain, "CAA")
            caa = ','.join([answer.to_text() for answer in answers])
        except:
            caa = None

        # Get TXT records of domain
        try:
            answers = dns.resolver.query(self.domain, "TXT")
            txt = ','.join([answer.to_text() for answer in answers])
        except:
            txt = None

        return {
            "ip" : ip,
            "caa" : caa,
            "txt" : txt
        }
