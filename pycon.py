import os
import requests
import json
import sys
import sublist3r
import dns.resolver
import takeover.takeover
import subprocess
import nmap
import traceback
from pathlib import Path

from icecream import ic
from pythonping import ping


import EyeWitness

DNS_RECORD_TYPES = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA']


def query_sublist3r(domain, no_threads=40, savefile=None,
                  ports=None, silent=True, verbose=False, 
                  enable_bruteforce=False, engines=None):
    return sublist3r.main(domain, no_threads, savefile, ports, silent, 
                          verbose, enable_bruteforce, engines)


def query_dns(domain, file):
    info = {"domain": domain}
    for qtype in DNS_RECORD_TYPES:
        answer = dns.resolver.resolve(domain, qtype, raise_on_no_answer=False)
        if answer.rrset is not None:
            info[qtype] = str(answer.rrset)

    with open(file, 'w') as f:
        json.dump(info, f)

    return info


def is_alive(host, count=3, timeout=2):
    try:
        ping_result = ping(target=host, count=count, timeout=timeout)
    except Exception as e:
        return False

    return ping_result.stats_packets_returned > 0


def has_http(domain):
    print(domain)
    return  200 <= requests.get(f"http://{domain}").status_code < 300


def has_https(domain):
    return  200 <= requests.get(f"https://{domain}").status_code < 300


def check_takeover(domain, file, threads=1, d_list=None, 
                   proxy=None, timeout=None, process=False, 
                   verbose=False):
    takeover.takeover.main(domain=domain, threads=threads, d_list=d_list,
                           proxy=proxy, output=file, timeout=timeout, 
                           process=process, verbose=verbose)


def check_eyewitness(file_domains, dir):
    args = ("python", "EyeWitness/Python/EyeWitness.py", "-f", file_domains, "-d", "eyewitness_results/", "--resolve", "--no-prompt")
    popen = subprocess.Popen(args, ouput=subprocess.PIPE)
    popen.wait()
    output = popen.stdout.read()
    with open(dir / "eyewitness.output", 'w') as f:
        f.write(output)
    

def check_waybackurls(host, with_subs=False):
    if with_subs:
        url = 'http://web.archive.org/cdx/search/cdx?url=*.%s/*&output=json&fl=original&collapse=urlkey' % host
    else:
        url = 'http://web.archive.org/cdx/search/cdx?url=%s/*&output=json&fl=original&collapse=urlkey' % host
    r = requests.get(url)
    results = r.json()
    return results[1:]





def check_nmap(domain, file):
    nm = nmap.PortScanner()
    nm.scan(domain, arguments='-T4')
    nm=nm.scaninfo()
    with open(file, 'w') as results:
        json.dump(nm, results)
    return nm

def make_dir(dir):
    if not os.path.isdir(dir):
        os.mkdir(dir)

def make_directories(dir, domains):
    for domain in domains:
        make_dir(os.path.join(dir, domain))


RESULTS = "results"
def pycon(domain):
    make_dir(RESULTS)
    print("sublist3r")
    sublist3r_results = query_sublist3r(domain, 
                        savefile=os.path.join(RESULTS, "sublist3r_results.txt"))
    sublist3r_results.append(domain)
    print("active domain filter")
    ic(sublist3r_results)
    active_domains = [domain if is_alive(domain) else '' for domain in sublist3r_results]
    active_domains = list(filter(None, active_domains))
    make_directories(RESULTS, active_domains)
    print("scraping active domain info")
    for domain in active_domains:
        print("check nmap")
        check_nmap(domain, os.path.join(RESULTS, domain, "nmap.json"))
        print("query dns")
        query_dns(domain, os.path.join(RESULTS, domain, "dns.json"))
        print("check waybackurl")
        check_waybackurls(domain, os.path.join(RESULTS, domain, "waybackurl.txt"))
        print("takevers")
        check_takeover(domain, os.path.join(RESULTS, domain, "takeover.txt"))
        
    ic(active_domains)
    web_domains = [domain if (has_http(domain) or has_https(domain)) else '' for domain in active_domains]
    print(web_domains)
    print("Eyewitness")


    
    





        




        

def main():
    pass

def test(domain="youtube.com"):
    # ic(query_sublist3r(domain))
    # ic(query_dns(domain, "dns.json"))
    # ic(ping_host(domain))
    # check_takeover(domain="youtube.com")
    # check_eyewitness("urls.txt")
    # ic(check_waybackurls(domain))
    # ic(check_nmap(domain, "test.txt"))
    pycon(domain)

if __name__ == "__main__":
    test()
