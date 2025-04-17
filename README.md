![dns-triage logo](assets/logo-dns-triage.png)

dns-triage.py
=============

A simple Python script to do quick, targeted recon of a given domain.

Checks:
- DNS records
- *Selected* subdomains - chosen for high value and frequency
- Third-party services

Usage
-----

```bash
python3 dns-triage.py <Second-Level Domain> [Optional DNS Server] [Optional Microsoft Tenant]
```

Example: 

```
python3 dns-triage.py example.com
```


Sample output
-------------

*Note: Real domain names and IP addresses have been replaced with example.com and 127.0.0.1 in the sample output.*

```
================================================================================
Gathering DNS records for parent domain, example.com...
================================================================================

A records for example.com
-------------------------
127.0.0.1

NS records for example.com
--------------------------
ns1.domaincontrol.com.
ns2.domaincontrol.com.

MX records for example.com
--------------------------
10 mxa-00000000.gslb.pphosted.com.
10 mxb-00000000.gslb.pphosted.com.

[!] ProofPoint detected as default incoming email service.
    Numeric ID from the subdomain name may be used here:
    - https://app.explore.proofpoint.com/v2/apps/login/?usercenter=false


================================================================================
Checking subdomains of example.com...
================================================================================

Checking for wildcard subdomain records...
------------------------------------------
[+] No wildcard DNS records found. Output should be pretty reliable.

Checking for Microsoft Exchange Smart Hosts...
----------------------------------------------
[+] example-com.mail.protection.outlook.com > 127.0.0.1
    [💥]  Microsoft Exchange Online smart host detected!
        - May allow email spoofing. See:
          https://www.blackhillsinfosec.com/spoofing-microsoft-365-like-its-1995/

Checking for Microsoft Services...
----------------------------------
[💥] autodiscover.example.com > email.example.com.
[💥] POSSIBLE ON-PREMISES SERVICE: Microsoft Exchange/OWA
    Recommend investigating these URLs:
    - https://autodiscover.example.com/
    - https://autodiscover.example.com/autodiscover/autodiscover.xml
    - https://autodiscover.example.com/owa/
    - https://autodiscover.example.com/EWS/Exchange.asmx

Checking for common subdomains...
---------------------------------
[+] securemail.example.com > 127.0.0.1
    Possible Secure Mail app. Try:
    - https://securemail.example.com/
    - https://securemail.example.com/encrypt  (ProofPoint Encrypted Mail user registration)
    - https://securemail.example.com/s/preregister  (Zix Secure Message Center user registration)

[+] vdi.example.com > vdi-portal.example.com.
    Possible VPN/remote access.


================================================================================
Checking third-party services of "example"...
================================================================================

[+] example.service-now.com - ServiceNow likely in use!

[+] example.zoom.us - Zoom likely in use!

[+] example.zoom.com - Zoom likely in use!

[+] example.webex.com - Webex likely in use!
    - Try browsing to this subdomain, and look in Web UI for calendar/meetings.
    - Try Google-dorking this domain to find links to meetings.

[+] https://example.slack.com - Slack likely in use!

[+] https://example.atlassian.net - Atlassian (Jira/Confluence/Trello) likely in use!
    - https://example.atlassian.net/login.jsp


DONE!
```


See also
--------

- NetSPI script for automated analysis of TXT records
    - https://raw.githubusercontent.com/NetSPI/PowerShell/master/Resolve-DnsDomainValidationToken.ps1



Changelog
---------

- **2025-04-17**
    - Added Amazon AWS Apps for WorkDocs and Device Code authentication detection.

- **2025-01-28**
    - Added "Investor login" (www.secureaccountview.com) to third-party services.

- **2024-11-25**
    - Added common investor portals to list of interesting subdomains.
    - Happy Thanksgiving! 🦃

- **2024-10-01**
    - Added `horizon` to the list of interesting subdomains. Possible VMware Horizon.
    - Added FreshWorks.

- **2024-09-07**
	- Added `view` to the list of interesting subdomains.

- **2024-07-24**
	- Added Jamf.

- **2024-07-22**
	- Added MobileIron.

- **2024-03-26**
    - Added Duo.

- **2024-03-10**
	- Fixed old bash reference in README.md.
	- Updated random string generation to match length of target and orgname strings.
	- Added Workday.

- **2024-03-08**
    - Added GitHub.
    - Added Discord.

- **2024-03-05**
    - Added Perks at Work.

- **2024-03-04**
	- Added common subdomains and info for Azure Multi-Factor Authentication Server.

- **2024-02-23**
	- Rewrote `dns-triage` in Python as `dns-triage.py`. ***The Python version will replace the Bash version, moving forward.***

- **2024-02-01**
    - Added .my.salesforce.com additional detection for Salesforce.
    - Added Organization Account Alias/ID URL for Proofpoint.

- **2023-11-01**
    - Corrected the ProofPoint securemail registration URL.

- **2023-10-31: Happy Halloween! 🎃**
	- Public release on GitHub.
	- Added check for ADP payroll URL. 

- **2023-09-20**
    - Added check for Box.com - learned from Beau's "Breaching the Cloud" class. 🙂

- **2023-08-14**
    - Added check for MFA subdomain, additional Zoom vanity URL format.

- **2023-06-20**
    - Added check for Webex third-party service subdomain.

- **2023-03-28**
    - Added ability to optionally specify a target DNS server.
    - Fixed a typo that was breaking "fs" subdomain detection.
    - Updated Slack detection to be via web instead of DNS.
    - Updated third party DNS check to better account for multiple IP addresses returned for a subdomain.
    - Added web-based detection of Atlassian (Jira/Confluence/Trello).

- **2023-01-17** 
    - Added new user registration URL for Zix Secure Message Center.

- **2023-01-10** 
    - Added additional URLs and guidance for on-prem Microsoft services.

- **2022-12-05**
    - Added checks for third-party services:
        - Okta
        - ServiceNow
        - Salesforce
        - Slack
        - Zoom (vanity URL)
        - Ivanti

- **2022-11-04**
    - Initial internal (BHIS) release.
