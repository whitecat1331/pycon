
from dotenv import load_dotenv
from icecream import ic

from pycon import *

def test() -> None:
    """
    Test function to demonstrate individual functionalities of the Pycon tool using environment variables.
    Must have the environment variable DOMAIN set. 
    
    Returns:
        None
    """
    load_dotenv()
    domain = os.getenv("DOMAIN")
    domains = [domain]
    ic(query_sublist3r(domain))
    ic(query_dns(domain))
    ic(is_alive(domain))
    ic(check_takeover(domains))
    ic(check_waybackurls(domain))
    ic(check_nmap(domain))
    ic(check_whois(domain))
    ic(check_sslmate(domain))
    ic(filter_out_of_scope(["dev.example.com", "admin.example.com", "example.com", "dev.outofscope.com", "admin.outofscope.com", "admin.outofscope2.com"], 
                            ["*.outofscope.com", "*.outofscope2.com"]))
    ic(scrape_subdomains(domains))
    ic(scrape_domain_info(domain))
    ic(scrape_domains_info(domains))
    # this will also call check_eyewitness
    capture_web_screenshots(domains)
    # pycon(domain)
    pass

if __name__ == "__main__":
    test()
