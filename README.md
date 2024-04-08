# Description

The Pycon Security Toolkit is a versatile 
Python script designed to streamline various security-related 
tasks commonly performed during cybersecurity assessments and 
penetration testing activities. This script empowers security 
professionals with a comprehensive set of features, including 
subdomain enumeration, DNS queries, host alive checks, 
HTTP/HTTPS availability checks, subdomain takeover vulnerability 
detection, web page screenshot capture, WHOIS information retrieval, 
Wayback URLs check, port scanning, SSL certificate information retrieval, 
and out-of-scope domain filtering

The goal of this project is to create a simple and easy way to gather information and 
visual images of domains found through sublist3r, waybackurls, etc. 

This project is licensed is under GPL-3. This means that anyone can copy, distribute, and modify any of the code written in this repository.

This project was tested and developed on an Ubuntu based OS. All other operating systems 
might encounter an error. 

# Requirements
* python3.11+


# Manuel Installation

```
git clone --recurse-submodules https://github.com/whitecat1331/pycon.git

cd pycon

pip install -r requirements.txt

python pycon.py --help
```

# Quick Installation

```
git clone --recurse-submodules https://github.com/whitecat1331/pycon.git

cd pycon

pip install .

pycon --help
```

<b>or if developing</b>

```
git clone --recurse-submodules https://github.com/whitecat1331/pycon.git

cd pycon

pip install --editable .

pycon --help
```

# Usage

```
Usage: pycon.py [OPTIONS] IN_SCOPE

Options:
  -o, --output FILENAME
  -oos, --out-of-scope FILENAME
  --help                         Show this message and exit.

```

# Current Features

## <u>Reconnaissance</u>
* Subdomain Enumeration
* Asset Filtering (Ping, HTTP)
* EyeWitness Snapshots

# Potential Features
* Add visual UI for all information found on the domains. 
