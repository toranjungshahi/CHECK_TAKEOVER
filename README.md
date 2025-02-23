# CHECK_TAKEOVER

Sub-domain takeover is used by attackers as a phishing attack, where the traffic intended for legitimate websites are redirected to attacker’s site. 
Thereby, the attacker can steal important information of users such as personal credentials and card 
details.

*CHECK_TAKEOVER* is a project to build sub-domain takeover checker tool. It is written in python programming language.
This tool checks the vulnerability of subdomains associated to a domain by enumerating the subdomains of a given domain. List of subdomains are obtained from  theHarvester tool (https://github.com/laramies/theHarvester) which 
is used to gather open source intelligence (OSINT) on a company or domain.

## Installation/Usage

Clone the **theHarvester** tool from https://github.com/laramies/theHarvester into working directory.

Install requirements by running:
```
 !pip install -r requirements.txt
 
```
Run check_takeover tool by running:
```
Python check_takeover.py -d DOMAIN -s SOURCE -f FILENAME 

Where DOMAIN  is the domain name of a company to check for vulnerability, example : 
example-domain.com.au 
SOURCE is the list of OSINT sources to gather list of subdomains associated with the domain. 
Example : Baidu,rapiddns,github 
FILENAME is the name of the file to save list of subdomains. If none given, saves the file as base domain name.
```

A successful run would look like below screenshot. Ignore other files in file explorer window.

![Screenshot of successful run of the tool](https://github.com/toranjungshahi/something_awesome/blob/master/images/example%20run.PNG)

## Future Improvements

This tool checks AWS and GitHub domain service providers. Can add other service providers to check against.
Automating to gather list of service providers to check against would be awesome.
