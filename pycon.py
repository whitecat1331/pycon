import os
import requests
import json
import sys
import sublist3r
import dns.resolver
import takeover.takeover
import subprocess
import shutil
import nmap
import traceback
import whois
import datetime
from tqdm import tqdm 

from icecream import ic
from pythonping import ping

sys.path.insert(0, os.path.join("EyeWitness", "Python"))

import EyeWitness

DNS_RECORD_TYPES = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA']


def serialize_datetime(obj): 
    if isinstance(obj, datetime.datetime): 
        return obj.isoformat() 
    raise TypeError("Type not serializable") 

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
    return  200 <= requests.get(f"http://{domain}").status_code < 300

def has_https(domain):
    return  200 <= requests.get(f"https://{domain}").status_code < 300

def check_takeover(domain, file, threads=1, d_list=None, 
                   proxy=None, timeout=None, process=False, 
                   verbose=False, stdout=None):
    takeover.takeover.main(domain=domain, threads=threads, d_list=d_list,
                           proxy=proxy, output=file, timeout=timeout, 
                           process=process, verbose=verbose, stdout=stdout)

def setArgv(args):
    temp_argv = sys.argv
    sys.argv = sys.argv[0:1]
    sys.argv.extend(args)
    return temp_argv


def check_eyewitness(file_domains, dir, silent=False):
    args = ("-f", file_domains, "-d", "eyewitness_results", 
            "--resolve", "--no-prompt", "--delay", "3", 
            "--timeout", "60")

    temp_argv = setArgv(args)
    EyeWitness.main()
    sys.argv = temp_argv
    """
    if silent:
        popen = subprocess.Popen(args, stdout=subprocess.PIPE)
        popen.wait()
        output = popen.stdout.read()
        with open("eyewitness.output", 'w') as f:
            f.write(str(output))
    else:
        popen = subprocess.Popen(args)
        popen.wait()
    """

    shutil.move("eyewitness_results", dir)
    dir = os.path.join(dir, "eyewitness_results")
    shutil.move("geckodriver.log", dir)

def check_whois(domain, file):
    results = dict(whois.whois(domain))
    with open(file, 'w') as f:
        json.dump(results, f, default=serialize_datetime)
    return results

def check_waybackurls(host, file, with_subs=False):
    if with_subs:
        url = 'http://web.archive.org/cdx/search/cdx?url=*.%s/*&output=json&fl=original&collapse=urlkey' % host
    else:
        url = 'http://web.archive.org/cdx/search/cdx?url=%s/*&output=json&fl=original&collapse=urlkey' % host
    r = requests.get(url)
    results = r.json()
    with open(file, 'w') as f:
        json.dump(results, f)
    return results[1:]

def check_nmap(domain, file):
    nm = nmap.PortScanner()
    scan = nm.scan(domain, arguments='-T4')
    with open(file, 'w') as results:
        json.dump(scan, results)
    return scan

def make_dir(dir):
    if not os.path.isdir(dir):
        os.mkdir(dir)

def make_directories(dir, domains):
    for domain in domains:
        make_dir(os.path.join(dir, domain))




RESULTS = "results"
def pycon(domain):
    if os.path.isdir(RESULTS):
        shutil.rmtree(RESULTS)
    make_dir(RESULTS)
    print("sublist3r")
    sublist3r_results = query_sublist3r(domain, 
                        savefile=os.path.join(RESULTS, "sublist3r_results.txt"))
    sublist3r_results.append(domain)
    ic(sublist3r_results)
    print("active domain filter")
    active_domains = [domain if is_alive(domain) else '' for domain in sublist3r_results]
    active_domains = list(filter(None, active_domains))
    ic(active_domains)
    make_directories(RESULTS, active_domains)
    print("scraping active domain info")
    for domain in tqdm(active_domains):
        check_nmap(domain, os.path.join(RESULTS, domain, "nmap.json"))
        query_dns(domain, os.path.join(RESULTS, domain, "dns.json"))
        check_waybackurls(domain, os.path.join(RESULTS, domain, "waybackurl.json"))
        check_takeover(domain, os.path.join(RESULTS, domain, "takeover.txt"),
                       stdout=os.path.join(RESULTS, domain, "takeover.out"))
        check_whois(domain, os.path.join(RESULTS, domain, "nmap.json"))

        
    ic(active_domains)
    web_domains = [domain if (has_http(domain) or has_https(domain)) else '' for domain in active_domains]
    web_domains = list(filter(None, web_domains))
    ic(web_domains)
    print("Eyewitness")
    web_domain_path = os.path.join(RESULTS, "web_domains.txt")
    with open(web_domain_path, 'w') as f:
        for domain in web_domains:
            f.write(domain + '\n')

    check_eyewitness(web_domain_path, RESULTS)



    
    





        




        

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
    # ic(check_whois(domain, "test.json"))
    pycon(domain)

if __name__ == "__main__":
    test()
