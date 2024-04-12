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
from pythonping import ping
from typing import *

sys.path.insert(0, os.path.join("EyeWitness", "Python"))
import EyeWitness

logging.basicConfig(filename="pycon.log",
                    format='%(asctime)s %(message)s',
                    filemode='w')
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)


def serialize_datetime(obj: datetime.datetime) -> str:  
    """
    Serializes a datetime object to ISO format for JSON serialization.
    
    Parameters:
        obj (datetime.datetime): The datetime object to serialize.
        
    Returns:
        str: The serialized datetime object.
    """
    if isinstance(obj, datetime.datetime): 
        return obj.isoformat() 
    raise TypeError("Type not serializable") 

def query_sublist3r(domain: str, no_threads: int = 40, savefile: str = None,
                  ports: List[int] = None, silent: bool = True, verbose: bool = True, 
                  enable_bruteforce: bool = False, engines: List[str] = None) -> List[str]:
    """
    Queries Sublist3r for subdomains of a given domain.
    
    Parameters:
        domain (str): The target domain to enumerate subdomains for.
        no_threads (int): Number of threads to use for parallel subdomain enumeration (default is 40).
        savefile (str): File to save the results (default is None).
        ports (list): Ports to scan for in subdomain enumeration (default is None).
        silent (bool): Whether to run Sublist3r silently (default is True).
        verbose (bool): Whether to enable verbose mode in Sublist3r (default is False).
        enable_bruteforce (bool): Whether to enable bruteforce subdomain enumeration in Sublist3r (default is False).
        engines (list): Subdomain search engines to use (default is None).
    
    Returns:
        list: List of subdomains found.
    """
    return sublist3r.main(domain, no_threads, savefile, ports, silent, 
                          verbose, enable_bruteforce, engines)

PUBLIC_NAMESERVERS = [
               "8.8.8.8", "8.8.4.4", # Google
               "1.1.1.1", "1.0.0.1", # Cloudflare
               "208.67.222.222", "208.67.220.220", # OpenDNS
               "208.67.222.220", "208.67.220.222"
]

def query_dns(domain: str, limit: int=3)-> Dict[str, Union[str, Dict[str, str]]]:
    """
    Performs DNS queries for various record types for a given domain.
    
    Parameters:
        domain (str): The target domain to query DNS records for.
        limit (int): Number of attempts to make for each DNS query (default is 3).
    
    Returns:
        dict: Dictionary containing domain information including DNS records.
    """
    DNS_RECORD_TYPES = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA']
    resolver = dns.resolver.Resolver(configure=False)
    resolver.timeout = 60
    resolver.lifetime = 60
    resolver.nameservers.extend(PUBLIC_NAMESERVERS)
    info = {"domain": domain}
    success = False
    attempts = 0
    while not success and attempts < limit:
        try: 
            for qtype in DNS_RECORD_TYPES:
                answer = resolver.resolve(domain, qtype, raise_on_no_answer=False)
                if answer.rrset is not None:
                    info[qtype] = str(answer.rrset)
            success = True

        except dns.resolver.LifetimeTimeout as lt:
            logging.info(f"{lt}\nattempt {attempts} out of {limit}")
        except Exception as e:
            logging.error(e)
        attempts += 1



    if attempts >= limit and not success:
        logging.warning(f"Attempt limit for {domain} reached.")
        logging.debug(f"Info: {info}\nAttempts: {attempts}\nLimit{limit}")


    return info

def is_alive(host: str, count: int = 3, timeout: int = 2) -> bool:
    """
    Checks if a host is alive by sending ICMP ping packets.
    
    Parameters:
        host (str): The target host to check.
        count (int): Number of ping packets to send (default is 3).
        timeout (int): Timeout in seconds for each ping packet (default is 2).
    
    Returns:
        bool: True if the host is alive, False otherwise.
    """
    try:
        ping_result = ping(target=host, count=count, timeout=timeout)
        return ping_result.stats_packets_returned > 0
    except Exception as e:
        logging.error(e)
    return False


def has_http(domain: str, scheme="http://") -> bool:
    """
    Checks if HTTP service is available for a given domain.
    
    Parameters:
        domain (str): The target domain to check.
    
    Returns:
        bool: True if HTTP service is available, False otherwise.
    """
    try:
        return  200 <= requests.get(scheme + domain, headers={"User-Agent": "Pycon"}).status_code < 300
    except requests.exceptions.ConnectionError as reC:
        logging.info("HTTP Not Found", reC)
    except Exception as e:
        logging.error(e)

    return False

def has_https(domain: str) -> bool:
    """
    Checks if HTTPS service is available for a given domain.
    
    Parameters:
        domain (str): The target domain to check.
    
    Returns:
        bool: True if HTTPS service is available, False otherwise.
    """
    try:
        return  200 <= requests.get(f"https://{domain}", headers={"User-Agent": "Pycon"}).status_code < 300
    except requests.exceptions.ConnectionError as reC:
        logging.info("HTTPS Not Found", reC)
    except Exception as e:
        logging.error(e)

    return False





def check_takeover(domains: List[str], file: str = None, threads: int = 1, d_list: List[str] = None, 
                   proxy: str = None, timeout: int = None, process: bool = False, 
                   verbose: bool = False, stdout: str = None) -> str:
    """
    Checks for potential subdomain takeover vulnerabilities.
    
    Parameters:
        domains (List[str]): List of domains to check for takeover vulnerabilities.
        file (str): File to save the output (default is None).
        threads (int): Number of threads to use for checking (default is 1).
        d_list (List[str]): List of domains to check for takeover vulnerabilities (default is None).
        proxy: Proxy server to use for the request (default is None).
        timeout (int): Timeout in seconds for each request (default is None).
        process (bool): Whether to process the input list of domains (default is False).
        verbose (bool): Whether to enable verbose mode (default is False).
        stdout (str): File object to redirect output to (default is None).
    
    Returns:
        str: Output of the takeover check.
    """
    return (takeover.takeover.main(domains=domains, threads=threads, d_list=d_list,
                           proxy=proxy, output=file, timeout=timeout, 
                           process=process, verbose=verbose))

def check_eyewitness(file_domains: str) -> None:
    """
    Captures screenshots of web pages associated with specified domains using EyeWitness.
    
    Parameters:
        file_domains (str): File containing a list of domains to capture screenshots for.
    
    Returns:
        None
    """
    try:
        EyeWitness.main(f=file_domains, d="eyewitness_results", 
                    resolve=True, no_prompt=True, delay=3, 
                    timeout=60)
    except requests.exceptions.ConnectionError as reC:
        logging.info(reC)
    except Exception as e:
        logging.error(e)



def check_whois(domain: str) -> Dict[str, Union[str, List[str]]]:
    """
    Retrieves WHOIS information for a given domain.
    
    Parameters:
        domain (str): The target domain to retrieve WHOIS information for.
    
    Returns:
        Dict[str, Union[str, List[str]]]: WHOIS information as a dictionary.
    """
    results = dict(whois.whois(domain))
    return results

def check_waybackurls(host: str, with_subs: bool = False) -> List[str]:
    """
    Queries the Wayback Machine for archived URLs associated with a given host.
    
    Parameters:
        host (str): The target host to query Wayback Machine for.
        with_subs (bool): Whether to include subdomains in the query (default is False).
    
    Returns:
        List[str]: List of archived URLs.
    """
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

def check_nmap(domain: str) -> Dict[str, Dict[str, Union[str, Dict[str, Union[str, int]]]]]:
    """
    Performs a port scan on a given domain using nmap.
    
    Parameters:
        domain (str): The target domain to perform the port scan on.
    
    Returns:
        Dict[str, Dict[str, Union[str, Dict[str, Union[str, int]]]]]: Scan results.
    """
    nm = nmap.PortScanner()
    scan = nm.scan(domain, arguments='-T4')
    return scan

def check_sslmate(domain: str) -> set:
    """
    Retrieves SSL certificate information for a given domain using certspotter.
    
    Parameters:
        domain (str): The target domain to retrieve SSL certificate information for.
    
    Returns:
        set: Set of DNS names associated with the SSL certificate.
    """
    dns_names = set()
    base_url = f"https://api.certspotter.com/v1/issuances?domain={domain}&expand=dns_names&expand=issuer&expand=revocation&expand=problem_reporting&expand=cert_der"
    response = requests.get(base_url).json()

    if not response:
        return {}

    if isinstance(response, dict) and response["code"] == "rate_limited":
        return {}


    for obj in response:
        dns_names.update(obj["dns_names"])

    return dns_names


def filter_out_of_scope(domains: List[str], out_of_scope_domains: List[str] = None) -> List[str]:
    """
    Filters out-of-scope domains from a list of domains.
    
    Parameters:
        domains (List[str]): List of domains to filter.
        out_of_scope_domains (List[str]): List of out-of-scope domains (default is None).
    
    Returns:
        List[str]: Filtered list of domains.
    """
    if not out_of_scope_domains:
        return domains
    filtered_domains = []
    for domain in tqdm(domains):
        for out_of_scope in out_of_scope_domains:
            reg_domain = out_of_scope.replace('.', '\\.').replace('*', ".*")
            if re.match(reg_domain, domain):
                filtered_domains.append(domain)

    return [domain for domain in domains if domain not in filtered_domains]

def scrape_subdomains(in_scope_domains: List[str]) -> List[str]:
    """
    Scrapes subdomains using various techniques for a list of in-scope domains.
    
    Parameters:
        in_scope_domains (List[str]): List of in-scope domains to scrape subdomains for.
    
    Returns:
        List[str]: List of scraped subdomains.
    """
    all_domains = []
    for domain in tqdm(in_scope_domains):
        all_domains.extend(list(query_sublist3r(domain)))
        all_domains.extend(check_sslmate(domain))
        # all_domains.extend(check_waybackurls(domain, with_subs=True))

    return all_domains

def filter_active(all_domains: List[str]) -> List[str]:
    """
    Filters active domains from a list of domains.
    
    Parameters:
        all_domains (List[str]): List of domains to filter.
    
    Returns:
        List[str]: Filtered list of active domains.
    """
    active_domains = [domain if is_alive(domain) else '' for domain in tqdm(all_domains)]
    return list(filter(None, active_domains))

def filter_web(all_domains: List[str]) -> List[str]:
    """
    Filters domains with HTTP/HTTPS services from a list of domains.
    
    Parameters:
        all_domains (List[str]): List of domains to filter.
    
    Returns:
        List[str]: Filtered list of domains with HTTP/HTTPS services.
    """
    web_domains = [domain if (has_http(domain) or has_https(domain)) else '' for domain in tqdm(all_domains)]
    return list(filter(None, web_domains))

def scrape_domain_info(domain: str) -> Dict[str, Union[str, Dict[str, Union[str, int]]]]:
    """
    Scrapes information for a single domain.
    
    Parameters:
        domain (str): The target domain to scrape information for.
    
    Returns:
        Dict[str, Union[str, Dict[str, Union[str, int]]]]: Dictionary containing information about the domain.
    """
    domain_info = {}
    domain_info["domain"] = domain
    domain_info.update(check_nmap(domain))
    domain_info["dns"] = query_dns(domain)
    domain_info["whois"] = check_whois(domain)
    # domain_info["takeover"] = check_takeover(domain) 

    return domain_info

def scrape_domains_info(domains: List[str]) -> List[Dict[str, Union[str, Dict[str, Union[str, int]]]]]:
    """
    Scrapes information for multiple domains.
    
    Parameters:
        domains (List[str]): List of domains to scrape information for.
    
    Returns:
        List[Dict[str, Union[str, Dict[str, Union[str, int]]]]]: List of dictionaries containing information about the domains.
    """
    domains_info = []
    for domain in tqdm(domains):
        domains_info.append(scrape_domain_info(domain))
    return domains_info


def capture_web_screenshots(all_domains: List[str]) -> None:
    """
    Captures screenshots of web pages associated with specified domains.
    
    Parameters:
        all_domains (List[str]): List of domains to capture screenshots for.
    
    Returns:
        None
    """
    web_domains = filter_web(all_domains)
    urls_handle, path = tempfile.mkstemp()
    with open(urls_handle, 'w') as f:
        for domain in web_domains:
            f.write(domain + '\n')
    check_eyewitness(path)
    os.remove(path)

RESULTS = "results"
def pycon(out_of_scope_domains: List[str], in_scope_domains: List[str], output: str = None) -> List[Dict[str, Union[str, Dict[str, Union[str, int]]]]]:
    """
    Main function to orchestrate the entire security assessment process.
    
    Parameters:
        out_of_scope_domains (List[str]): List of out-of-scope domains.
        in_scope_domains (List[str]): List of in-scope domains.
        output (str): Output file to save the results (default is None).
    
    Returns:
        List[Dict[str, Union[str, Dict[str, Union[str, int]]]]]: List of dictionaries containing information about the domains.
    """
    if out_of_scope_domains:
        out_of_scope_domains = out_of_scope_domains.read().split()

    in_scope_domains = in_scope_domains.read().split()

    directory, name = os.path.split(output.name)

    if directory == '':
        directory = RESULTS 

    try:
        os.mkdir(directory)
    except FileExistsError as fee:
        logging.info(f"Directory alredy exists {fee}")
        directory += datetime.datetime.now().strftime("_%d_%m_%Y_%H_%M_%S")
        logging.info(f"Creating new directory {directory}")
        os.mkdir(directory)
    except Exception as e:
        logging.critical(e)
        sys.exit(1)
    finally:
        os.chdir(directory)



    # find subdomains
    click.echo("Scrape subdomains")
    all_domains = scrape_subdomains(in_scope_domains)
    click.echo(f"{len(all_domains)} subdomains found")
    click.echo("Filter out of scope")
    all_domains = filter_out_of_scope(all_domains, out_of_scope_domains=out_of_scope_domains)
    click.echo("Filter active domains")
    all_domains = filter_active(all_domains)
    all_domains.extend(in_scope_domains)
    all_domains = set(all_domains)
    click.echo(f"All Domains\n{all_domains}")
    # find info for all active domains
    click.echo("Domain Info")
    domains_info = scrape_domains_info(all_domains)
    click.echo(domains_info)
    if output:
        with open(name, "w") as f:
            json.dump(domains_info, f, default=serialize_datetime)
    click.echo("Takeover")
    check_takeover(domains=all_domains)
    # take a screenshot of all web hosts domains
    click.echo("Eyewitness")
    capture_web_screenshots(all_domains)
    return domains_info

    


# silent mode        
@click.command()
@click.option("-o", "--output", "output", type=click.File('w'))
@click.option("-oos", "--out-of-scope", "out_of_scope", type=click.File('r'))
@click.argument("in_scope", type=click.File('r'))
def main(output: str, out_of_scope: str, in_scope: str) -> None:
    """
    Command-line interface for running Pycon security assessment tool.
    
    Parameters:
        output (str): Output file to save the results.
        out_of_scope (str): File containing a list of out-of-scope domains.
        in_scope (str): File containing a list of in-scope domains.
    
    Returns:
        None
    """
    pycon(out_of_scope, in_scope, output=output)


if __name__ == "__main__":
    main()

