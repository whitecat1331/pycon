import os
import re
import logging
import tempfile
import csv
import click
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



def serialize_datetime(obj): 
    if isinstance(obj, datetime.datetime): 
        return obj.isoformat() 
    raise TypeError("Type not serializable") 

def query_sublist3r(domain, no_threads=40, savefile=None,
                  ports=None, silent=True, verbose=False, 
                  enable_bruteforce=False, engines=None):
    return sublist3r.main(domain, no_threads, savefile, ports, silent, 
                          verbose, enable_bruteforce, engines)

PUBLIC_NAMESERVERS = [
               "8.8.8.8", "8.8.4.4", # Google
               "1.1.1.1", "1.0.0.1", # Cloudflare
               "208.67.222.222", "208.67.220.220", # OpenDNS
               "208.67.222.220", "208.67.220.222"
]

def query_dns(domain):
    DNS_RECORD_TYPES = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA']
    resolver = dns.resolver.Resolver(configure=False)
    resolver.timeout = 60
    resolver.lifetime = 60
    resolver.nameservers.extend(PUBLIC_NAMESERVERS)
    info = {"domain": domain}
    for qtype in DNS_RECORD_TYPES:
        answer = resolver.resolve(domain, qtype, raise_on_no_answer=False)
        if answer.rrset is not None:
            info[qtype] = str(answer.rrset)

    return info

def is_alive(host, count=3, timeout=2):
    try:
        ping_result = ping(target=host, count=count, timeout=timeout)
    except Exception as e:
        return False

    return ping_result.stats_packets_returned > 0

def has_http(domain):
    return  200 <= requests.get(f"http://{domain}", headers={"User-Agent": "Pycon"}).status_code < 300

def has_https(domain):
    return  200 <= requests.get(f"https://{domain}", headers={"User-Agent": "Pycon"}).status_code < 300

def check_takeover(domains, file=None, threads=1, d_list=None, 
                   proxy=None, timeout=None, process=False, 
                   verbose=False, stdout=None):
    return (takeover.takeover.main(domains=domains, threads=threads, d_list=d_list,
                           proxy=proxy, output=file, timeout=timeout, 
                           process=process, verbose=verbose))

def setArgv(args):
    temp_argv = sys.argv
    sys.argv = sys.argv[0:1]
    sys.argv.extend(args)
    return temp_argv


def check_eyewitness(file_domains):
    EyeWitness.main(f=file_domains, d="eyewitness_results", 
                    resolve=True, no_prompt=True, delay=3, 
                    timeout=60)


def check_whois(domain):
    results = dict(whois.whois(domain))
    return results

def check_waybackurls(host, with_subs=False):
    if with_subs:
        url = 'http://web.archive.org/cdx/search/cdx?url=*.%s/*&output=json&fl=original&collapse=urlkey' % host
    else:
        url = 'http://web.archive.org/cdx/search/cdx?url=%s/*&output=json&fl=original&collapse=urlkey' % host
    r = requests.get(url)
    results = r.json()
    domains = []
    for contained_domain in results:
        for domain in contained_domain:
            domains.append(re.sub("http(s)?://", "", domain))

    return domains

def check_nmap(domain):
    nm = nmap.PortScanner()
    scan = nm.scan(domain, arguments='-T4')
    return scan

def check_sslmate(domain):
    base_url = f"https://api.certspotter.com/v1/issuances?domain={domain}&expand=dns_names&expand=issuer&expand=revocation&expand=problem_reporting&expand=cert_der"
    response = requests.get(base_url).json()

    dns_names = set()
    for obj in response:
        dns_names.update(obj["dns_names"])

    return dns_names



def make_dir(dir):
    if not os.path.isdir(dir):
        os.mkdir(dir)

def make_directories(dir, domains):
    for domain in domains:
        make_dir(os.path.join(dir, domain))


def filter_out_of_scope(domains, out_of_scope_domains=None):
    if not out_of_scope_domains:
        return domains
    filtered_domains = []
    for domain in domains:
        for out_of_scope in out_of_scope_domains:
            reg_domain = out_of_scope.replace('.', '\\.').replace('*', ".*")
            if re.match(reg_domain, domain):
                filtered_domains.append(domain)

    return [domain for domain in domains if domain not in filtered_domains]

def scrape_subdomains(in_scope_domains):
    all_domains = []
    for domain in in_scope_domains:
        all_domains.extend(list(query_sublist3r(domain)))
        all_domains.extend(check_sslmate(domain))
        all_domains.extend(check_waybackurls(domain, with_subs=True))

    return all_domains

def filter_active(all_domains):
    active_domains = [domain if is_alive(domain) else '' for domain in all_domains]
    return list(filter(None, active_domains))

def filter_web(all_domains):
    web_domains = [domain if (has_http(domain) or has_https(domain)) else '' for domain in all_domains]
    return list(filter(None, web_domains))



def scrape_domain_info(domain):
    domain_info = {}
    domain_info["domain"] = domain
    domain_info.update(check_nmap(domain))
    domain_info["dns"] = query_dns(domain)
    domain_info["whois"] = check_whois(domain)
    # domain_info["takeover"] = check_takeover(domain) 

    return domain_info

def scrape_domains_info(domains):
    domains_info = []
    for domain in tqdm(domains):
        domains_info.append(scrape_domain_info(domain))
    return domains_info


def capture_web_screenshots(all_domains):
    web_domains = filter_web(all_domains)
    urls_handle, path = tempfile.mkstemp()
    with open(urls_handle, 'w') as f:
        for domain in web_domains:
            f.write(domain + '\n')
    check_eyewitness(path)
    os.remove(path)



RESULTS = "results"
def pycon(out_of_scope_domains, in_scope_domains, output=None):

    if os.path.isdir(RESULTS):
        shutil.rmtree(RESULTS)

    if out_of_scope_domains:
        out_of_scope_domains = out_of_scope_domains.read().split()

    in_scope_domains = in_scope_domains.read().split()


    # find subdomains
    print("Find subdomains")
    all_domains = scrape_subdomains(in_scope_domains)
    all_domains = filter_out_of_scope(all_domains, out_of_scope_domains=out_of_scope_domains)
    all_domains = filter_active(all_domains)
    all_domains.extend(in_scope_domains)
    all_domains = set(all_domains)
    # find info for all active domains
    print("Domain Info")
    domains_info = scrape_domains_info(all_domains)
    if output:
        json.dump(domains_info, output, default=serialize_datetime)
    print("Takeover")
    check_takeover(domains=all_domains)
    # take a screenshot of all web hosts domains
    print("Eyewitness")
    capture_web_screenshots(all_domains)
    return ic(domains_info)

    



# silent mode        
@click.command()
@click.option("-o", "--output", "output", type=click.File('w'))
@click.option("-oos", "--out-of-scope", "out_of_scope", type=click.File('r'))
@click.argument("in_scope", type=click.File('r'))
def main(output, out_of_scope, in_scope):
    pycon(out_of_scope, in_scope, output=output)


def test(domain="fireblocks.com"):
    # ic(query_sublist3r(domain))
    # ic(query_dns(domain))
    # ic(is_alive(domain))
    # ic(check_takeover({'blog.fireblocks.com',
    #               'checkout.fireblocks.com',
    #               'community.fireblocks.com',
    #               'developers.fireblocks.com',
    #               'emails.fireblocks.com',
    #               'eu.status.fireblocks.com',
    #               'eu2.status.fireblocks.com',
    #               'fireblocks.com',
    #               'hireblocks.fireblocks.com',
    #               'info.fireblocks.com',
    #               'marketplaceapi.gcp.fireblocks.com',
    #               'ncw-developers.fireblocks.com',
    #               'sandbox.status.fireblocks.com',
    #               'shopit.fireblocks.com',
    #               'status.fireblocks.com',
    #               'www.fireblocks.com'}))
    # ic(check_waybackurls(domain))
    # ic(check_nmap(domain))
    # ic(check_whois(domain))
    # ic(check_sslmate(domain))
    # ic(filter_out_of_scope(["dev.example.com", "admin.example.com", "example.com", "dev.outofscope.com", "admin.outofscope.com", "admin.outofscope2.com"], 
    #                         ["*.outofscope.com", "*.outofscope2.com"]))
    # check_eyewitness("urls.txt")
    # ic(scrape_subdomains([domain]))
    # ic(scrape_domain_info(domain))
    # ic(scrape_domains_info([domain]))
    # capture_web_screenshots([domain])
    # pycon(domain)
    pass

if __name__ == "__main__":
    main()
