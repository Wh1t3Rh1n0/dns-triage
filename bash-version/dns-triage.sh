#!/bin/bash
if [ "$1" == "" ] || [ "$1" == "--help" ] || [ "$1" == "-h" ] ; then
    echo
    echo "dns-triage -- by Wh1t3Rh1n0"
    echo "=========="
    echo "Check default and really, really common DNS records to quickly"
    echo "identify external services and other interesting things about"
    echo "your target."
    echo
    echo "Usage: $0 <Second-Level Domain> [DNS Server]"
    echo
    echo "Example: $0 google.com"
    exit
fi


USER_AGENT='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36 Edg/111.0.1661.54'

TARGET_SLD=$1
TEMPFILE=.tmp.dnstriage
rm -f $TEMPFILE 2>/dev/null >/dev/null

if [ "$2" != "" ] ; then
    echo "Using DNS server: $2"
    DNS_SRV=@$2
else
    unset DNS_SRV
fi



# Check to be sure `dig` is present. Some distros don't install it by default.
if [ ! -e "$(which dig)" ] ; then
    echo "ERROR: `dig` command not found."
    echo "Please install dig (sudo apt install dnsutils) to use this script."
    exit
fi

# Check to be sure `curl` is present. Some distros don't install it by default.
if [ ! -e "$(which curl)" ] ; then
    echo "ERROR: `curl` command not found."
    echo "Please install curl (sudo apt install curl) to use this script."
    exit
fi



# Function to grep TXT records for indicators of third-party services and display the output
grep-txt() {
    # usage: grep-txt <FILE WITH TXT RECORDS> <SERVICE NAME> <REGEX>
    indicator=$(grep -Eio "$3" $1 | head -n 1)
    if [ "$indicator" ] ; then 
        echo "  - $2 (Indicator: $indicator)"
    fi
}

# Check if the target DNS record points to a Microsoft-owned domain.
is-microsoft() {
    TARGET=$1
    if [ "$(dig +short lyncdiscover.wayfair.com | grep -Ei '\.(office|outlook|lync)\.com\.?$' | tr -d '\r' | tr -d '\n')" != "" ] ; then
        echo "true"
    else
        echo "false"
    fi
}


check-type() {
    rm -f $TEMPFILE >/dev/null 2>/dev/null
    if [ "$1" == "any" ] ; then
        dig -t $1 $TARGET_SLD $DNS_SRV | grep -vE '^$|^;' > $TEMPFILE
    else
        dig -t $1 $TARGET_SLD $DNS_SRV | grep -vE '^$|^;' | grep -vE "IN$(echo -e '\t')SOA" > $TEMPFILE
    fi

    if [ "$(wc -l $TEMPFILE 2>/dev/null | cut -d ' ' -f 1 )" != "0" ] && [ "$(wc -l $TEMPFILE 2>/dev/null )" != "" ] ; then
        echo "------------------------------------------------------------------------------"
        echo "$TARGET_SLD: TYPE=$1 $2"
        echo "------------------------------------------------------------------------------"
        cat $TEMPFILE
        echo
        
        if [ "$1" == mx ] && [ "$(grep -i 'pphosted.com' $TEMPFILE | head -n1 )" != "" ] ; then
            echo "[*] Proofpoint detected - Try entering the numeric ID in the subdomain here:"
            echo "    - https://app.explore.proofpoint.com/v2/apps/login/?usercenter=false"
            echo
        fi
        
        rm -f $TEMPFILE 2>/dev/null >/dev/null
    fi
}


# Check if a domain or subdomain exists.
# If found, print a description and optional URLs generated from the domain name.
# Usage: check-domain <Domain/Subdomain> <Description> [Optional URL paths (up to 7)]
check-domain() {
    rm -f $TEMPFILE 2>/dev/null >/dev/null
    dig $1 $DNS_SRV | grep -vE '^$|^;' | grep -vE "IN$(echo -e '\t')SOA" > $TEMPFILE

    if [ "$(wc -l $TEMPFILE 2>/dev/null | cut -d ' ' -f 1 )" != "0" ] && [ "$(wc -l $TEMPFILE 2>/dev/null )" != "" ] ; then
        echo "------------------------------------------------------------------------------"
        echo "$1 $2"
        if [ "$3" != "" ] ; then
            echo "* Try visiting these URLs:"
            echo "  - https://$1$3"
        fi
        if [ "$4" != "" ] ; then
            echo "  - https://$1$4"
        fi
        if [ "$5" != "" ] ; then
            echo "  - https://$1$5"
        fi
        if [ "$6" != "" ] ; then
            echo "  - https://$1$6"
        fi
        if [ "$7" != "" ] ; then
            echo "  - https://$1$7"
        fi
        if [ "$8" != "" ] ; then
            echo "  - https://$1$8"
        fi
        if [ "$9" != "" ] ; then
            echo "  - https://$1$9"
        fi
        echo "------------------------------------------------------------------------------"
        cat $TEMPFILE
        echo
    fi
    rm -f $TEMPFILE 2>/dev/null >/dev/null
}

echo



dig-okta() {
    OKTA_RESULT="$(dig +short $1 $DNS_SRV | grep -iF 'okta.com' | head -n1)"
    if [ "$OKTA_RESULT" != "" ] ; then
        echo "$1 => Resolved to: $OKTA_RESULT"
    fi
}

check-okta() {
    rm -f $TEMPFILE 2>/dev/null >/dev/null

    ( dig-okta sso.$1
      dig-okta login.$1
      dig-okta okta.$1
      dig-okta signin.$1
      dig-okta signon.$1
      dig-okta portal.$1
    
      ORG=$(echo $1 | sed -E 's/\.[a-zA-Z0-9]+$//g')
      dig-okta $ORG.okta.com
    ) > $TEMPFILE
    
    if [ "$(wc -l $TEMPFILE 2>/dev/null | cut -d ' ' -f 1 )" != "0" ] && [ "$(wc -l $TEMPFILE 2>/dev/null )" != "" ] ; then
        echo "------------------------------------------------------------------------------"
        echo "Okta found! - The following subdomains resolve to okta.com"
        echo "------------------------------------------------------------------------------"
        cat $TEMPFILE
        echo
    fi
    rm -f $TEMPFILE 2>/dev/null >/dev/null
}


check-thirdparty-simple() {
    SERVICE_NAME="$1"
    SERVICE_DOM=$2
    TARGET_SLD=$3
    ORG=$(echo $3 | sed -E 's/\.[a-zA-Z0-9]+$//g')
    EXTRA=$4
    EXTRA2=$5
    EXTRA3=$6

    if [ "$(dig +short $ORG.$SERVICE_DOM $DNS_SRV | sort -fu | tr '\n' ' ')" != "$(dig +short $RANDOM.$SERVICE_DOM $DNS_SRV | sort -fu | tr '\n' ' ')" ] ; then
        echo "------------------------------------------------------------------------------"
        echo "$SERVICE_NAME likely in use!"
        if [ "$EXTRA" != "" ] ; then echo "$EXTRA" ; fi
        if [ "$EXTRA2" != "" ] ; then echo "$EXTRA2" ; fi
        if [ "$EXTRA3" != "" ] ; then echo "$EXTRA3" ; fi
        echo "------------------------------------------------------------------------------"
        echo "$ORG.$SERVICE_DOM"
        echo
    fi
}


check-thirdparty-https-length() {
    SERVICE_NAME="$1"
    SERVICE_DOM=$2
    TARGET_SLD=$3
    TARGET_PATH=$4
    ORG=$(echo $3 | sed -E 's/\.[a-zA-Z0-9]+$//g')
    
    if [ "$(curl -ksA "$USER_AGENT" https://$ORG.$SERVICE_DOM$TARGET_PATH | wc -c )" != "$(curl -ksA "$USER_AGENT" https://$RANDOM.$SERVICE_DOM$TARGET_PATH | wc -c )" ] ; then
        echo "------------------------------------------------------------------------------"
        echo "$SERVICE_NAME likely in use! (Web-based detection)"
        echo "------------------------------------------------------------------------------"
        echo "https://$ORG.$SERVICE_DOM$TARGET_PATH"
        echo
    fi
}

# Really simple start to doing detections based on redirects.
# If a redirect (HTTP 30X) is detected, it evaluates as true. Otherwise, false.
check-redirect() {
    SERVICE_NAME="$1"
    TARGET_SLD=$2
    SERVICE_URL=$3
    
    TARGET_NAME=$(echo $TARGET_SLD | sed -E 's/\.[^.]*$//g')
    
    if [ "$(curl -vks -A "$USER_AGENT" "$SERVICE_URL/$TARGET_NAME" 2>&1 | grep -E '< HTTP/.*30[0-9]')" != "" ] ; then
        echo "------------------------------------------------------------------------------"
        echo "$SERVICE_NAME likely in use! (Web-based detection)"
        echo "------------------------------------------------------------------------------"
        echo "$SERVICE_URL/$TARGET_NAME"
        echo    
    fi
}





check-type any
check-type srv
check-type txt
check-type mx
check-type ns

echo "------------------------------------------------------------------------------"
echo "Checking for wildcard DNS records..."
echo "------------------------------------------------------------------------------"
WILDSUB=WILDCARD-LITERALLY-ANYTHING-$RANDOM
dig $WILDSUB.$TARGET_SLD $DNS_SRV | grep -vE '^$|^;' | grep -vE "IN$(echo -e '\t')SOA" > $TEMPFILE
if [ "$(wc -l $TEMPFILE 2>/dev/null | cut -d ' ' -f 1 )" != "0" ] && [ "$(wc -l $TEMPFILE 2>/dev/null )" != "" ] ; then
    echo "WILDCARD DNS RECORDS ENABLED! Watch out for possible false positives!"
    echo
    cat $TEMPFILE
else
    echo "No wildcard DNS records found. Output should be pretty reliable."
fi
echo
rm -f $TEMPFILE 2>/dev/null >/dev/null


check-domain autodiscover.$TARGET_SLD "-- May be on-prem Exchange/OWA if not a Microsoft-owned IP" "/" "/autodiscover/autodiscover.xml" "/owa/" "/EWS/Exchange.asmx"
check-domain lyncdiscover.$TARGET_SLD "-- May be on-prem Lync/Skype For Business if not a Microsoft-owned IP" "/  (Check XML for references to other URLs/servers)" "/scheduler/  (Also try this URL on other servers found in XML)" "/dialin/  (Also try this URL on other servers found in XML)"
check-domain activesync.$TARGET_SLD "-- May be on-prem ActiveSync if not a Microsoft-owned IP" "/" "/Microsoft-Server-ActiveSync"

# check-domain securemail.$TARGET_SLD "-- Possible Secure Mail app" "/" "/encrypt  (ProofPoint Encrypted Mail user registration)" "/securereader/init.jsf  (ProofPoint Encrypted Mail user registration step 2)" "/securereader/registration.jsf  (ProofPoint Encrypted Mail user registration step 3)" "/s/preregister  (Zix Secure Message Center user registration)"

check-domain securemail.$TARGET_SLD "-- Possible Secure Mail app" "/" "/encrypt  (ProofPoint Encrypted Mail user registration)" "/s/preregister  (Zix Secure Message Center user registration)"

check-domain fs.$TARGET_SLD "-- Possible ADFS portal" "/adfs/ls/idpinitiatedsignon.htm"
check-domain adfs.$TARGET_SLD "-- Possible ADFS portal" "/adfs/ls/idpinitiatedsignon.htm"
check-domain mail.$TARGET_SLD "-- Check if different from MX. May be legacy/spoofable/OWA." "/" "/autodiscover/autodiscover.xml" "/owa/" "/EWS/Exchange.asmx"
check-domain owa.$TARGET_SLD
check-domain webmail.$TARGET_SLD

check-domain vpn.$TARGET_SLD "-- Possible VPN/remote access"
check-domain remote.$TARGET_SLD "-- Possible VPN/remote access"
check-domain anyconnect.$TARGET_SLD "-- Possible VPN/remote access"
check-domain portal.$TARGET_SLD "-- Possible VPN/remote access"
check-domain cisco.$TARGET_SLD "-- Possible VPN/remote access"
check-domain rdp.$TARGET_SLD "-- Possible VPN/remote access"
check-domain access.$TARGET_SLD "-- Possible VPN/remote access"
check-domain remoteaccess.$TARGET_SLD "-- Possible VPN/remote access"
check-domain citrix.$TARGET_SLD "-- Possible VPN/remote access"
check-domain vdi.$TARGET_SLD "-- Possible VPN/remote access"
check-domain xen.$TARGET_SLD "-- Possible VPN/remote access"

check-domain mobile.$TARGET_SLD "-- Sometimes VPN/remote access"

check-domain sharepoint.$TARGET_SLD

check-domain intranet.$TARGET_SLD
check-domain helpdesk.$TARGET_SLD
check-domain help.$TARGET_SLD
check-domain support.$TARGET_SLD

check-domain mfa.$TARGET_SLD

check-domain hr.$TARGET_SLD
check-domain humanresources.$TARGET_SLD
check-domain directory.$TARGET_SLD


outlook_sd=$( echo "$TARGET_SLD" | tr '.' '-' ).mail.protection.outlook.com
check-domain $outlook_sd "-- MS365 SMTP. May allow spoofing."

outlook_sd=$( echo "$TARGET_SLD" | tr '.' '-' )01i.mail.protection.outlook.com
check-domain $outlook_sd "-- MS365 SMTP. May allow spoofing."

if [ "$( echo $TARGET_SLD | grep -Eo '[-]' | sort -u )" != "" ] ; then
    outlook_sd=$( echo "$TARGET_SLD" | tr -d '-' | tr '.' '-' ).mail.protection.outlook.com
    check-domain $outlook_sd "-- MS365 SMTP. May allow spoofing."

    outlook_sd=$( echo "$TARGET_SLD" | tr -d '-' | tr '.' '-' )01i.mail.protection.outlook.com
    check-domain $outlook_sd "-- MS365 SMTP. May allow spoofing."
fi

check-domain securemail-$TARGET_SLD "-- Zix Secure Message Center. May allow registration."

check-okta $TARGET_SLD

check-thirdparty-simple "ServiceNow" service-now.com $TARGET_SLD
check-thirdparty-simple "SalesForce" salesforce.com $TARGET_SLD
check-thirdparty-simple "SalesForce" my.salesforce.com $TARGET_SLD
check-thirdparty-simple 'Zoom vanity URL' zoom.us $TARGET_SLD
check-thirdparty-simple 'Zoom vanity URL' zoom.com $TARGET_SLD

check-thirdparty-simple "Ivanti" saasit.com $TARGET_SLD
check-thirdparty-simple "Webex" webex.com $TARGET_SLD '* Try browsing to this subdomain, and look in Web UI for calendar/meetings.' '* Try Google-dorking this domain to find links to meetings.'

check-thirdparty-https-length "Slack" slack.com $TARGET_SLD
check-thirdparty-https-length "Atlassian (Jira/Confluence/Trello)" atlassian.net $TARGET_SLD /login.jsp

check-thirdparty-https-length "Box.com" account.box.com $TARGET_SLD /login

check-redirect "ADP Payroll" $TARGET_SLD https://portal.globalview.adp.com
    









