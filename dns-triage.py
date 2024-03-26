#!/usr/bin/env python3

import sys
import re
import random, string
import requests
import dns.resolver


usage = """
dns-triage.py -- by Wh1t3Rh1n0
=============

Quick, targeted recon of a given domain. Checks:
- DNS records
- Selected subdomains - chosen for high value and frequency
- Third-party services

Recommended: Provide the Microsoft tenant name (___.onmicrosoft.com) if it is
known. Otherwise, the script will attempt to guess.

Usage: python3 dns-triage.py <Domain> [Nameserver] [Microsoft Tenant]
"""


if len(sys.argv) < 2 or "-h" in sys.argv or '--help' in sys.argv:
    print(usage)
    exit()


target = sys.argv[1]
orgname = target.split('.')[0]

#if len(sys.argv) > 2: dns_resolver = sys.argv[2]
#else: dns_resolver = False

#if len(sys.argv) > 3: ms_tenant = sys.argv[3]
#else: ms_tenant = None


def resolve(target, record_type=None):
    """Resolve the target DNS record. Return None if no record found."""

    if dns_resolver:
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers=[dns_resolver]
    else:
        resolver = dns.resolver.Resolver()

    try:
        if record_type == None:
            answers: dns.resolver.Answer = resolver.resolve(target)
        else:
            answers: dns.resolver.Answer = resolver.resolve(target, record_type)
    except:
        return None
    output = []
    for rdata in (answers):
        output.append(str(rdata))
    return output


def print_heading(text, extra_line=False, underline='-', width=None,
    top_line=False):
    """Print an underlined heading."""

    print()
    if top_line:
        if width:
            print(underline * width)
        else:
            print(underline * len(text))
    print(text)
    if width:
        print(underline * width)
    else:
        print(underline * len(text))
    if extra_line: print()


def print_list(input_list, sort=False):
    """Optionally sort and print a list."""

    if sort: input_list.sort()
    for line in input_list: print(line)


def check_type(target, record_type=None, sort=False):
    """Print and return all DNS records of a given type."""

    records = resolve(target, record_type)
    if records:
        print_heading("%s records for %s" % (record_type.upper(), target))
        print_list(records, sort)
    return records


def randomword(length):
    """Print a string of random letters."""

    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(length))


def resolve_host_record(target):
    """
    Return the CNAME, A, or AAAA record of a given hostname (in that order).
    """

    record_types = ['CNAME', 'A', 'AAAA']
    for record_type in record_types:
        record = resolve(target, record_type)
        if record != None:
            return record
    return None


def re_search_list(regex, target_list):
    """Search a list for a given regular expression."""

    if target_list:
        r = re.compile(regex, re.IGNORECASE)
        newlist = list(filter(r.match, target_list))
        if ( len(newlist) > 0):
            return newlist
        else:
            return False
    else:
        return None


def is_microsoft_hosted(result):
    """
    Return true if the given DNS lookup result points to a Microsoft-owned
    domain.
    """

    if result:
        if re_search_list(r'.*\.(outlook|office|lync|microsoftonline)\.com\.?$', result):
            return True
        else:
            return False


def check_dns_record_exists(fqdn, info_list, check_if_ms_hosted=False, 
                            wildcard_result=None, target=target):
    """
    Check if a DNS record resolves successfully. If it does, display
    the lines in info_list.
    """

    if len(info_list) > 0: service_name = info_list[0]
    else: service_name = None

    if len(info_list) > 1: info_sublist = info_list[1:]
    else: info_sublist = None

    result = resolve_host_record(fqdn)
    
    #print("Result: ")
    #print(result)
    #print("Wildcard: ")
    #print(wildcard_result)
    
    if result == wildcard_result and wildcard_result != None:
        #print("[!] Probable false positive - wildcard subdomain record match.")
        return
    
    if result:

        # Handle on-premises Microsoft services
        if check_if_ms_hosted:
            if not is_microsoft_hosted(result):
                print('[💥] ' + fqdn + ' > ' + result[0])
                print(f"[💥] POSSIBLE ON-PREMISES SERVICE: {service_name}")
                print(f"    Recommend investigating these URLs:")
                if info_sublist:
                    for line in info_sublist: print('    ' + line)
            else:
                print('[+] ' + fqdn + ' > ' + result[0])

        # Continue with all other output.
        else:
            print('[+] ' + fqdn + ' > ' + result[0])
            for line in info_list:
                print('    ' + line)

        # Handle Okta portals.
        if result and target.lower() != 'okta.com' and is_okta_hosted(result):
            print("    [!] Okta login portal detected")

        print()
        return result
    return result


def convert_to_smarthost_list(domain):
    """
    Return a list of all possible Smart Host hostnames for a given domain name.
    """

    domain_v1 = domain.replace('.','-')

    domain_v2 = domain.replace('-','').replace('.','-')

    smarthost_variants = [
        f'{domain_v1}.mail.protection.outlook.com',
        f'{domain_v2}.mail.protection.outlook.com',
        ]

    for n in range(97,123):
        c = chr(n)
        smarthost_variants.append(f'{domain_v1}01{c}.mail.protection.outlook.com')
        smarthost_variants.append(f'{domain_v2}01{c}.mail.protection.outlook.com')

    smarthost_variants = list(set(smarthost_variants))
    smarthost_variants.sort()

    return smarthost_variants


def is_okta_hosted(result, target=target):
    """Return True of the given DNS lookup result resolves to Okta.com."""

    if result:
        if re_search_list(r'.*\.(okta.com)\.?$', result):
            return True
        else:
            return False


def different_records(fqdn1, fqdn2):
    """
    Compares the DNS records of two FQDNs. Returns True if they are different.
    Returns False if they are the same.
    """
    fqdn1_record = resolve_host_record(fqdn1)
    fqdn2_record = resolve_host_record(fqdn2)
    #print (f"FQDN1: {fqdn1} > {fqdn1_record}")
    #print (f"FQDN2: {fqdn2} > {fqdn2_record}")
    return ( fqdn1_record != fqdn2_record )


def check_thirdparty_by_dns_comparison(fqdn_template, info_list, 
                                       orgname=orgname, target=target):
    """
    Check if the value of the target DNS record matches the value of a randomly
    generated DNS record. If it does not match, display the lines in info_list.
    """

    if len(info_list) > 0:
        service_name = info_list[0]
    if len(info_list) > 1:
        info_sublist = info_list[1:]
    else:
        info_sublist = None

    random_value = 'UNLIKELY-' + randomword(8)
    target_fqdn = fqdn_template.replace('{orgname}', orgname).replace('{target}', target)
    random_fqdn = fqdn_template.replace('{orgname}', random_value).replace('{target}', random_value)
    if different_records(target_fqdn, random_fqdn):
        print(f'[+] {target_fqdn} - {service_name} likely in use!')
        if info_sublist:
            for line in info_sublist:
                print(f'    {line}')
        print()


def different_http_length(url1, url2):
    """
    Retrieve two URLs and then return True if the length of the data returned
    by each URL are different lengths.
    """

    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
    }

    try:
        response1 = requests.get(f'{url1}', headers=headers)
        response2 = requests.get(f'{url2}', headers=headers)
    except:
        return False

    len1 = len(response1.text)
    len2 = len(response2.text)

    #print(f'{len1} != {len2}')

    return ( len1 != len2 )


def check_thirdparty_by_http_length(url_template, info_list, orgname=orgname, 
                                    target=target):
    """
    Check if the length of the data retrieved from the target URL matches the
    length of the data from a URL containing a randomly generated value. If the
    two do not match, display the lines in info_list.
    """
    if len(info_list) > 0:
        service_name = info_list[0]
    if len(info_list) > 1:
        info_sublist = info_list[1:]
    else:
        info_sublist = None

    random_orgname = randomword(len(orgname))
    random_target = randomword(len(target))
    target_url = url_template.replace('{orgname}', orgname).replace('{target}', target)
    random_url = url_template.replace('{orgname}', random_orgname).replace('{target}',random_target)
    if different_http_length(target_url, random_url):
        print(f'[+] {target_url} - {service_name} likely in use!')
        if info_sublist:
            for line in info_sublist:
                print('    ' + line.format(**{'url':target_url}))
        print()


def different_http_status(url1, url2, follow_redirects=False):
    """
    Return True if the HTTP status code retrieved from two different URLs
    do not match.
    """

    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
    }

    try:
        response1 = requests.get(f'{url1}', headers=headers,
                                            allow_redirects=follow_redirects)

        response2 = requests.get(f'{url2}', headers=headers,
                                            allow_redirects=follow_redirects)
    except:
        return False

    return (response1.status_code != response2.status_code)


def check_thirdparty_by_http_status(url_template, info_list, orgname=orgname,
                                    target=target):
    """
    Check if the HTTP status code retrieved from the target URL matches the
    status code returned from a URL containing a randomly generated value. If
    the two do not match, display the lines in info_list.
    """
    if len(info_list) > 0:
        service_name = info_list[0]
    if len(info_list) > 1:
        info_sublist = info_list[1:]
    else:
        info_sublist = None

    random_orgname = randomword(len(orgname))
    random_target = randomword(len(target))
    target_url = url_template.replace('{orgname}', orgname).replace('{target}', target)
    random_url = url_template.replace('{orgname}', random_orgname).replace('{target}', random_target)
    if different_http_status(target_url, random_url):
        print(f'[+] {target_url} - {service_name} likely in use!')
        if info_sublist:
            for line in info_sublist:
                print('    ' + line.format(**{'url':target_url}))
        print()


# Parse additional command arguments.
dns_resolver = re_search_list(r'([0-9]{1,3}\.){3}[0-9]{1,3}', sys.argv)
if dns_resolver: dns_resolver = dns_resolver[0]
ms_tenant = re_search_list(r'.*\.onmicrosoft\.com', sys.argv)
if ms_tenant: ms_tenant = ms_tenant[0]


if dns_resolver:
    print(f"Using user-defined nameserver: {dns_resolver}")

print_heading(f"Gathering DNS records for parent domain, {target}...", False,
              '=', width=80, top_line=True)

cname_records = check_type(target, 'CNAME')
a_records = check_type(target, 'A')
aaaa_records = check_type(target, 'AAAA')
txt_records = check_type(target, 'TXT', sort=True)
srv_records = check_type(target, 'SRV')
#soa_records = check_type(target, 'SOA')
#cert_records = check_type(target, 'CERT')
#dnskey_records = check_type(target, 'DNSKEY')
uri_records = check_type(target, 'URI')
ns_records = check_type(target, 'NS', sort=True)
mx_records = check_type(target, 'MX')

# Check MX records to determine if ProofPoint is in use.
if mx_records:
    r = re.compile(r'.*\.pphosted\.com\.?$', re.IGNORECASE)
    newlist = list(filter(r.match, mx_records))
    if ( len(newlist) > 0):
        print()
        print("[!] ProofPoint detected as default incoming email service.")
        print("    Numeric ID from the subdomain name may be used here:")
        print("    - https://app.explore.proofpoint.com/v2/apps/login/?usercenter=false")


# Check for smart hosts.
print()
print_heading(f"Checking for Microsoft Exchange Smart Hosts...", False, '=', width=80,
              top_line=True)
if ms_tenant:
    smarthost_variants = [ ms_tenant.lower().replace('.onmicrosoft.com','') + 
                           '.mail.protection.outlook.com' ]
else:
    smarthost_variants = convert_to_smarthost_list(target)
smarthost_info = ['[💥]  Microsoft Exchange Online smart host detected!',
                  '    - May allow email spoofing. See:',
                  '      https://www.blackhillsinfosec.com/spoofing-microsoft-365-like-its-1995/',
                 ]
for smarthost in smarthost_variants:
    check_dns_record_exists(smarthost, smarthost_info)


# Beginning of subdomain checks.
#print()
print_heading(f"Checking subdomains of {target}...", False, '=', width=80,
              top_line=True)

print_heading("Checking for wildcard subdomain records...")
wildcard_subdomain = "WILDCARD-LITERALLY-ANYTHING-" + randomword(8) + "." + target
wildcard_info = ["[⚠️] WARNING: Wildcard subdomains found. Deploying countermeasures... 🦏", 
                 "     - Only displaying subdomains that resolve to a different value than the",
                 "       wildcard record.", ]
wildcard_result = check_dns_record_exists(wildcard_subdomain, wildcard_info)
if not wildcard_result:
    print("[+] No wildcard DNS records found. Output should be pretty reliable.")



exchange_urls = [ "- https://{fqdn}/",
                  "- https://{fqdn}/autodiscover/autodiscover.xml",
                  "- https://{fqdn}/owa/",
                  "- https://{fqdn}/EWS/Exchange.asmx",
                ]

ms_subdomain_targets = {
    'autodiscover.{target}': ['Microsoft Exchange/OWA'] +
                             exchange_urls,
    'owa.{target}': ['Possible Microsoft Exchange/OWA'] +
                             exchange_urls,
    'lyncdiscover.{target}': ['Microsoft Lync/Skype For Business',
                              "- https://{fqdn}/  (Check XML for references to other URLs/servers)",
                              "- https://{fqdn}/scheduler/  (Also try this URL on other servers found in XML)",
                              "- https://{fqdn}/dialin/  (Also try this URL on other servers found in XML)",
                             ],
    'activesync.{target}': ['Microsoft ActiveSync',
                            "- https://{fqdn}/",
                            "- https://{fqdn}/Microsoft-Server-ActiveSync",
                           ],
}


print_heading("Checking for Microsoft Services...")
for subdomain in ms_subdomain_targets.keys():
    fqdn = subdomain.format(**{'target': target})
    values={'fqdn': fqdn, 'subdomain': subdomain, 'target': target}
    subdomain_info = [line.format(**values) for line in ms_subdomain_targets[subdomain]]
    subdomain_exists = check_dns_record_exists(fqdn, subdomain_info,
                                               check_if_ms_hosted=True,
                                               wildcard_result=wildcard_result)



adfs_info = [ 'Possible ADFS portal',
              "- https://{fqdn}/adfs/ls/idpinitiatedsignon.htm" ]

vpn_info = [ 'Possible VPN/remote access.' ]

securemail_info = [ 'Possible Secure Mail app. Try:',
                    '- https://{fqdn}/',
                    '- https://{fqdn}/encrypt  (ProofPoint Encrypted Mail user registration)',
                    '- https://{fqdn}/s/preregister  (Zix Secure Message Center user registration)'
                  ]


mfa_portal_info = [ 'Possible Azure Multi-Factor Authentication Server. Try:',
                    '- https://{fqdn}/MultiFactorAuth/',
                  ]

subdomain_targets = {
    'securemail.{target}': securemail_info,
    'adfs.{target}': adfs_info,
    'fs.{target}': adfs_info,
    'mail.{target}': ["Possible web mail. Try:"] + exchange_urls,
    'webmail.{target}': ["Possible web mail. Try:"] + exchange_urls,
    'vpn.{target}': vpn_info,
    'remote.{target}': vpn_info,
    'anyconnect.{target}': vpn_info,
    'portal.{target}': vpn_info,
    'cisco.{target}': vpn_info,
    'rdp.{target}': vpn_info,
    'access.{target}': vpn_info,
    'remoteaccess.{target}': vpn_info,
    'citrix.{target}': vpn_info,
    'vdi.{target}': vpn_info,
    'xen.{target}': vpn_info,
    'mobile.{target}': [],
    'sharepoint.{target}': [],
    'intranet.{target}': [],
    'helpdesk.{target}': [],
    'help.{target}': [],
    'support.{target}': [],
    'hr.{target}': [],
    'humanresources.{target}': [],
    'directory.{target}': [],
    'sso.{target}': [],
    'login.{target}': [],
    'okta.{target}': ['Possible Okta portal.'],
    'signin.{target}': [],
    'signon.{target}': [],
    'mfa.{target}': mfa_portal_info,
    'mfaportal.{target}': mfa_portal_info,
    'azuremfa.{target}': mfa_portal_info,
    }

print_heading("Checking for interesting subdomains...")

check_dns_record_exists(f'securemail-{target}', securemail_info)

for subdomain in subdomain_targets.keys():
    fqdn = subdomain.format(**{'target': target})
    values={'fqdn': fqdn, 'subdomain': subdomain, 'target': target}
    subdomain_info = [line.format(**values) for line in subdomain_targets[subdomain]]
    result = check_dns_record_exists(fqdn, subdomain_info, 
                                     wildcard_result=wildcard_result)
    if result and target.lower() != 'okta.com' and is_okta_hosted(result):
        print("    [!] Okta login portal detected")
        print()


zoom_info_list = [ 'Zoom',
                   '- Try Google-dorking this domain to find links to meetings.',
                 ]

thirdparty_by_dns_comparison = {
    '{orgname}.okta.com': ["Okta"],
    '{orgname}.service-now.com': ["ServiceNow"],
    '{orgname}.salesforce.com': ['SalesForce'],
    '{orgname}.my.salesforce.com': ['SalesForce'],
    '{orgname}.zoom.us': zoom_info_list,
    '{orgname}.zoom.com': zoom_info_list,
    '{orgname}.saasit.com': ['Ivanti'],
    '{orgname}.login.duosecurity.com': ['Duo'],
    '{orgname}.webex.com': ['Webex',
                            '- Try browsing to this subdomain, and look in Web UI for calendar/meetings.',
                            '- Try Google-dorking this domain to find links to meetings.'],
}

print_heading(f'Checking third-party services of "{orgname}"...', True, '=',
              width=80, top_line=True)

for fqdn_template in thirdparty_by_dns_comparison.keys():
    info_list = thirdparty_by_dns_comparison[fqdn_template]
    check_thirdparty_by_dns_comparison(fqdn_template, info_list)



workday_info_list = [ 'Workday' ]

thirdparty_by_http_length_comparison = {
    'https://{orgname}.slack.com': ["Slack"],
    'https://{orgname}.atlassian.net': ['Atlassian (Jira/Confluence/Trello)',
                                         '- {url}/login.jsp'],
    'https://{orgname}.account.box.com': ['Box.com', '- {url}/login'],
    'https://{orgname}.corporateperks.com': ['Perks at Work'],
    'https://discord.com/invite/{orgname}': ['Discord'],
    # 'https://outlook.office365.com/owa/{target}': ['Outlook Web Access', '* Investigate: This sometimes redirects to on-premises services'],
    'https://wd3.myworkday.com/{orgname}/d/home.htmld': workday_info_list,
    'https://wd5.myworkday.com/{orgname}/d/home.htmld': workday_info_list,
    }

for url_template in thirdparty_by_http_length_comparison.keys():
    info_list = thirdparty_by_http_length_comparison[url_template]
    check_thirdparty_by_http_length(url_template, info_list)


thirdparty_by_http_status_comparison = {
    'https://portal.globalview.adp.com/{orgname}': ["ADP Payroll"],
    'https://github.com/{orgname}': ["GitHub"],
    }

for url_template in thirdparty_by_http_status_comparison.keys():
    info_list = thirdparty_by_http_status_comparison[url_template]
    check_thirdparty_by_http_status(url_template, info_list)

print()
print("DONE!")
