import os
import sublist3r
import dns.resolver
import takeover.takeover
from icecream import ic
from pythonping import ping

class Pycon:
    DNS_RECORD_TYPES = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA']
    def __init__(self, dmoain):
        self.root_domain = domain
        self.subdomains = []

    def get_subdomains(self):
        # sublist3r
        # knock
        pass

    @staticmethod
    def query_sublist3r(domain, no_threads=40, savefile=None,
                      ports=None, silent=True, verbose=False, 
                      enable_bruteforce=False, engines=None):
        return sublist3r.main(domain, no_threads, savefile, ports, silent, 
                              verbose, enable_bruteforce, engines)

    @staticmethod
    def query_dns(domain):
        info = {"domain": domain}
        for qtype in Pycon.DNS_RECORD_TYPES:
            answer = dns.resolver.resolve(domain, qtype, raise_on_no_answer=False)
            if answer.rrset is not None:
                info[qtype] = answer.rrset

        return info

    @staticmethod
    def is_alive(host, count=3, timeout=2):
        ping_result = ping(target=host, count=count, timeout=timeout)
        return ping_result.stats_packets_returned > 0

    @staticmethod
    def has_http(domain):
        return  200 <= requests.get(f"http://{domain}").status_code < 300

    @staticmethod
    def has_https(domain):
        return  200 <= requests.get(f"https://{domain}").status_code < 300

    @staticmethod
    def check_takeover(domain=None, threads=1, d_list=None, 
                       proxy=None, output="results/takeover_results.txt", 
                       timeout=None, process=False, verbose=True):
        takeover.takeover.main(domain=domain, threads=threads, d_list=d_list,
                               proxy=proxy, output=output, timeout=timeout, 
                               process=process, verbose=verbose)

        

def main():
    pass

def test(domain="amazon.com"):
    # ic(Pycon.query_sublist3r(domain))
    # ic(Pycon.query_dns(domain))
    # ic(Pycon.ping_host(domain))
    Pycon.check_takeover(domain="youtube.com")

if __name__ == "__main__":
    test()
