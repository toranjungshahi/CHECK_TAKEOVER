# -*- coding: utf-8 -*-
"""
Created on Thu Nov  2 12:18:16 2023

@author: toran
"""
import os
import requests
import dns.resolver 
import subprocess
import argparse
import json
from pathlib import Path
import re
import tldextract
import sys
from termcolor import colored

###### Interface argument parser############
parser = argparse.ArgumentParser( 
    description="This tool checks the vulnerability of subdomains associated to a domain.List of \
    subdomains are obtained from  theHarvester tool (https://github.com/laramies/theHarvester) which \
    is used to gather open source intelligence (OSINT) on a company or domain."
    )

parser.add_argument(
        "-d", "--domain", help="Company name or domain to search.", required=True
    )

parser.add_argument(
    "-f",
    "--filename",
    help="Save the results to an XML and JSON file.",
    type=str,
    default=None,
)

parser.add_argument(
        "-s",
        "--source",
        help="""anubis, baidu, bevigil, binaryedge, bing, bingapi, bufferoverun, brave,
                            censys, certspotter, criminalip, crtsh, dnsdumpster, duckduckgo, fullhunt, github-code,
                            hackertarget, hunter, hunterhow, intelx, netlas, onyphe, otx, pentesttools, projectdiscovery,
                            rapiddns, rocketreach, securityTrails, sitedossier, subdomaincenter, subdomainfinderc99, threatminer, tomba,
                            urlscan, virustotal, yahoo, zoomeye""",
        default = "baidu,rapiddns",
    )
args = parser.parse_args()
domain_name = args.domain
public_source = args.source
if args.filename == None: #if no file name given save file as base domain
    output_file = tldextract.extract(domain_name).domain
else:
    output_file = args.filename

############################################
#Run python theHarvester.py -d domain_name -b Source

theHarvester_path = 'theHarvester/theHarvester.py'
arguments = ['-d',domain_name,'-b',public_source,'-f',output_file]

subprocess_cmd = ['python',theHarvester_path] + arguments
if not os.path.isfile(output_file+'.json'):
    try:
        print(f'Gathering subdomains of {domain_name} .......')
        subprocess.run(subprocess_cmd,check=True,shell=True)
    except subprocess.CalledProcessError as e:
        print('Error occurred in theHarvester tool.\n',e)
    
# DNS resolver (you can use Google's public DNS server)
resolver = dns.resolver.Resolver()
resolver.nameservers = ["1.1.1.1"] #specify the address of remote full resolver

#Extract base domain from sub domain 
def extract_base_domain(subdomain):
    extracted = tldextract.extract(subdomain)
    base_domain = extracted.domain + '.' + extracted.suffix
    return base_domain

#check if CNAME base domain can be taken over
def check_registration(subdomain):
    base_domain = extract_base_domain(subdomain)
    #check if subdomain points to third-party service
    if base_domain is not domain_name:
        #check if base_domain available for registration
        try:
            answers = dns.resolver.resolve(base_domain, 'A')
            return False  # Domain has DNS records (not available)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return True  # Domain does not have DNS records (available)
        except Exception as e:
            print(f"An error occurred while checking {base_domain}: {e}")
            sys.exit()

################ AWS S3 buckets ################################    
#Checks if the subdomain's CNAME matches to any AWS S3 buckets
def match_CNAME_aws(subdomain):
    #Amazon S3 bucket types
    standard = r"^[a-z0-9\.\-]{0,63}\.?s3.amazonaws\.com$" # {bucketname}.s3.amazonaws.com
    # {bucketname}.s3(.|-){region}.amazonaws.com
    standard_regional = r"^[a-z0-9\.\-]{3,63}\.s3[\.-](eu|ap|us|ca|sa)-\w{2,14}-\d{1,2}\.amazonaws.com$" 
    # {bucketname}.s3-website(.|-){region}.amazonaws.com (+ possible China region)
    website_regional = r"^[a-z0-9\.\-]{3,63}\.s3-website[\.-](eu|ap|us|ca|sa|cn)-\w{2,14}-\d{1,2}\.amazonaws.com(\.cn)?$"
    # {bucketname}.s3.dualstack.{region}.amazonaws.com
    dualstack_regional = r"^[a-z0-9\.\-]{3,63}\.s3.dualstack\.(eu|ap|us|ca|sa)-\w{2,14}-\d{1,2}\.amazonaws.com$"
    
    #check if subdomain points to Amazon S3 buckets
    s3_buckets = [standard,standard_regional,website_regional,dualstack_regional]
    for bucket in s3_buckets:
        if re.match(bucket, subdomain):
            return True #Return true if subdomain matches with any of the buckets
        
    return False #Return false if the subdomain does not match with any of the buckets

#Check if the subdomain is vulnerable in AWS
def check_availability_aws(source_domain):
    source_domain = 'https://' + source_domain
    
    # Make an HTTP GET request to the source domain
    response = requests.get(source_domain)
    
    # Check if the response content contains the specified error messages
    error_messages = ['<Code>NoSuchBucket</Code>', '<li>Code: NoSuchBucket</li>']
    
    subdomain_takeover_possible = any(error_message in response.text for error_message in error_messages)
    
    if subdomain_takeover_possible:
        return True
    else:
        return False
############# AWS #########################

##############Check github ###########################
def match_CNAME_git(subdomain):
    #Match with github page
    github_page = r"^[a-z0-9\.\-]{0,70}\.?github\.io$"
    if re.match(github_page, subdomain):
        return True #Return true if subdomain matches with any of the buckets
        
    return False #Return false if the subdomain does not match with any of the buckets

#Check if the subdomain is vulnerable in GitHub
def check_availability_git(source_domain):
    source_domain = 'https://' + source_domain
    
    # Make an HTTP GET request to the source domain
    response = requests.get(source_domain)
    
    # Check if the response content contains the specified error messages
    error_message = "<strong>There isn't a GitHub Pages site here.</strong>"
    
    if error_message in response.text:
        return True
    else:
        return False
##################### Github ######################## 

#function to check in different serivce providers
def check_vulnerability(cname,subdomain):
    if check_registration(cname):
        print(f'{subdomain} is vulnerable to subdomain takeover!')
    elif match_CNAME_aws(cname):
        vulnearble_in_aws = check_availability_aws(cname)
        if vulnearble_in_aws:
            print(f'{subdomain} is VULNERABLE to subdomain takeover in AWS!')
    elif match_CNAME_git(cname):
        vulnerable_in_git = check_availability_git(cname)
        if vulnerable_in_git:
            print(f'{subdomain} is VULNERABLE to subdomain takeover in GitHub!')
    else:
        print(f'{subdomain} is NOT vulnerable to subdomain takeover.')   

#Read json file for list of subdomains

output_file = output_file + '.json'
file_path = Path(os.getcwd())/output_file

with open(file_path) as file:
    content = json.load(file)
print('Done.\nChecking subdomain takeover..........\n')

#check for take over
for rtype,subdomains in content.items():
    if rtype == 'hosts':#check for hosts only
        if not subdomains:#if empty
            print('No hosts with subdomains found.')
        else:
            for subdomain in subdomains: #for each hostname and it's CNAME/A record
                subdomain = subdomain.split(":")
                if len(subdomain) == 2:
                    cname = subdomain[1]
                    subdomain = subdomain[0]
                    #print(colored(f'\nChecking {subdomain} for take over.........\n','green','on_white'))
                    check_vulnerability(cname,subdomain)
        
                
                
                









