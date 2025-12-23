#!/bin/bash

echo -e "----Name Resolution Check:\n\n"
cat /etc/resolv.conf
echo ""
echo ""
echo ""


read -p "Continue? (Y/N): " confirm && [[ $confirm == [yY] || $confirm == [yY][eE][sS] ]] || exit 1


######## CONSTANTS
SUMMARY="extaid_summary.txt"



######## SUBDOMAIN ENUMERATION
echo -e "\n\n---- SUBDOMAIN ENUMERATION ----"

echo -n "Start sublist3r: "; date; while read -r DOMAIN; do sublist3r --domain $DOMAIN --no-color 2>/dev/null; done < scope_domains.txt; echo -n "End: "; date; | tee sublist3r_result.txt;

echo -n "Start subfinder: "; date; subfinder -update; subfinder -list scope_domains.txt -rl 10 -all -silent; echo -n "End: "; date; | tee subfinder_result.txt;

echo -n "Start theHarvester: "; date; while read -r DOMAIN; do theHarvester -q -d $DOMAIN -b all; done < scope_domains.txt; echo -n "End: "; date; | tee theHarvester_result.txt

cat sublist3r_result.txt subfinder_result.txt theHarvester_result.txt | grep -ivE "^[[:space:]]*$|^\[|\ |Enumerating|\@|https://|:|\*" | grep -iE ".agency|.ai|.bank|.biz|.ca|.co|.com|.digital|.fortisbankus|.info|.io|.law|.mobi|.net|.online|.org|.re|.realestate|.site|.sullicurt|.us" | sort | uniq > subdomains.txt

echo -n "Start dig: "; date; while read -r DOMAIN; do echo "DOMAIN: $DOMAIN"; dig $DOMAIN +short; done < subdomains.txt; echo -n "End: "; date; | tee resolved_domains_2_ips.txt;

## SUMMARY
echo "SUMMARY of external_aid.sh results" >> $SUMMARY
echo -e "\nSubdomain enumeration" >> $SUMMARY
echo -n "* Subdomains enumerated: " >> $SUMMARY; grep "" subdomains.txt -c >> $SUMMARY;





######## SUBDOMAIN VALIDATION
echo -e "\n\n---- SUBDOMAIN VALIDATION ----"

echo -n "Start eyewitness for subdomains: "; date; eyewitness -f subdomains.txt --timeout 15 --delay 10 --prepend-http --no-prompt -d eyewitness_result_subdomains; echo -n "End: "; date; | tee eyewitness_result.txt

echo -n "Start curl for subdomains: "; date; while read -r DOMAIN; do echo "SUBDOMAIN: $DOMAIN"; curl --silent --head --location --insecure --verbose --user-agent "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:139.0) Gecko/20100101 Firefox/139.0" "$DOMAIN" 2>&1; done < subdomains.txt; echo -n "End: "; date; | tee curl_result_subdomains.txt;

cat curl_result_subdomains.txt | grep -ivE "office365" | grep -iE "OPENED" | awk -F\  '{print $NF}' | sort | uniq > final_urls.txt;

echo -n "Start dnsrecon: "; date; while read -r DOMAIN; do dnsrecon -d $DOMAIN; echo ""; done < scope_domains.txt; echo -n "End: "; date; | tee dnsrecon_result.txt;

echo -n "Start zone transfer check: "; date; while read -r DOMAIN; do echo "\n\n-- Domain:\n$DOMAIN"; NS=$(dig +short ns "$DOMAIN" | head --lines=1); echo "-- Name servers:\n$NS"; echo "-- Zone transfer test result:"; dig axfr "$DOMAIN" @"$NS"; done < scope_domains.txt; echo -n "End: "; date; | tee zone_transfer_result.txt

echo -n "Start zone walking check: "; date; while read -r DOMAIN; do echo -e "\n\n\nTesting domain $DOMAIN for zone walking"; NS=$(dig +short ns "$DOMAIN" | head --lines=1); echo -e "\n\t* Name servers:\n$NS"; echo -e "\n\t* INVALID subdomain result:"; dig "rsmtest.$DOMAIN" +dnssec @"$NS" | grep -E "NSEC"; echo "\n\t* VALID subdomain result:"; dig "www.$DOMAIN" +dnssec @"$NS" | grep -E "RRSIG"; done < scope_domains.txt; echo -n "End: "; date; | tee zone_walking_result.txt

echo -n "Start subjacking: "; date; subjack -w scope_domains.txt -c ~/Tools/subjack/fingerprints.json -v; echo -n "End: "; date; | tee subjack_result.txt

## SUMMARY
echo -e "\n\nSubdomain validation" >> $SUMMARY
echo -n "* Subdomains with 'OPENED' state (active): " >> $SUMMARY; grep "" final_urls.txt -c >> $SUMMARY;
echo -n "* Subdomains with 404 page: " >> $SUMMARY; grep "404" curl_result_subdomains.txt -c >> $SUMMARY;
echo -n "* Subdomains without DNSSEC: " >> $SUMMARY; grep -iE "DNSSEC is not configured" dnsrecon_result.txt -c >> $SUMMARY;
echo -n "* Subdomains with p=none: " >> $SUMMARY; grep -iE "v=DMARC|p=" dnsrecon_result.txt | awk -F\; '{ print $1, $2 }' | grep -iE "v=|p=none" -c >> $SUMMARY;
echo -n "* Subdomains with ~all: " >> $SUMMARY; grep -iE "~all" dnsrecon_result.txt -c >> $SUMMARY;
echo -n "* Subdomains WITHOUT zone transfer problems: " >> $SUMMARY; grep -iE "Transfer failed" dnsrecon_result.txt -c >> $SUMMARY;
echo -n "* Subdomains with zone walking problems: " >> $SUMMARY; grep -iE "NSEC" zone_walking_result.txt | grep -iE "\!\." -c >> $SUMMARY;
echo -n "* Subdomains WITHOUT subdomain takeover problems: " >> $SUMMARY; grep -iE "Not vulnerable" subjacking_result.txt | sort | uniq | grep "" -c >> $SUMMARY;





######## PORT SCANNING
echo -e "\n\n---- PORT SCANNING ----"

nmap -iL scope_ips.txt -Pn --top-ports 1000 -n -sS -T4 --min-rate 1000 --scan-delay 100ms --max-retries 1 --max-rtt-timeout 1000ms --source-port 53 -oN nmap_result.nmap -v;

nmap -iL scope_ips.txt -Pn --top-ports 1000 -n -sU -T4 --min-rate 1000 --scan-delay 100ms --max-retries 1 --max-rtt-timeout 1000ms --source-port 53 -oN nmap_result_udp.nmap -v;

cat *.nmap | grep -iE "open|Nmap scan report" | grep -ivE "Warning|OpenBSD|OpenSSL|no-response|fingerprint|filtered" | awk '{ prevLine; { if(prevLine ~ /Nmap/ && $0 ~ /^[0-9]/) print prevLine } prevLine = $0 }' | awk -F\  '{print $NF}' | sed 's/[()]//g' | sort | uniq > active_hosts.txt;

PORTS=$(cat *.nmap | grep -iE "open|Nmap scan report" | grep -ivE "Warning|OpenBSD|OpenSSL|no-response|fingerprint|filtered|syn-ack ttl 51|syn-ack ttl 49" | awk -F\  '{print $1}' | sed -E 's/\b(\/tcp|\/udp|Nmap)\b//g' | sort | uniq | awk '{ printf sep $0; sep="," } END { print "" }' | awk '{print substr($0, 2, length($0))}');

nmap -iL active_hosts.txt -p$PORTS -n -Pn -sS -sU -sV -sC --max-retries 2 --source-port 53 -oN nmap_result_ports.nmap -v

cat *.nmap | grep -ivE "SF:| fixes|filtered|no-response" | grep -iE "open" | awk -F\  '{print $3}' | sed 's/\?//g' | sed 's/ssl\/http/https/g' | grep -iE "." | grep -ivE "^with$" | sort | uniq > unique_services.txt

while read -r SERVICE; do cat *.nmap | grep -ivE "closed|no-response|Warning|syn-ack ttl 51|syn-ack ttl 49" | grep -E "Nmap scan report|open" | grep -iE "Nmap scan report|$SERVICE " | awk '{ prevLine; { if(prevLine ~ /Nmap/ && $0 ~ /^[0-9]/) print prevLine, $1 } if($0 ~ /^[0-9]/){  } else {prevLine = $0} }' | awk -F\  '{print $(NF-1), $NF}' | sed 's/[()]//g' | sed 's/\ /:/g' | sed -E 's/(\/tcp|\/udp)//g' >> have_active_$SERVICE.txt; done < unique_services.txt

## SUMMARY
echo -e "\n\nPort scanning" >> $SUMMARY
echo -n "* Active hosts: " >> $SUMMARY; grep "" active_hosts.txt -c >> $SUMMARY;
echo -n "* Unique services: " >> $SUMMARY; grep "" unique_services.txt -c >> $SUMMARY;
echo -n "* * " >> $SUMMARY;
grep -iE "." unique_services.txt | grep -ivE "^with$" >> $SUMMARY;
echo "" >> $SUMMARY;







######## WEB CHECKS
echo -e "\n\n---- WEB CHECKS ----";

cat have_active_http* > have_web_ports_open.txt;

echo -n "Start eyewitness for hosts: "; date; eyewitness -f have_web_ports_open.txt --timeout 15 --delay 10 --prepend-http --no-prompt -d eyewitness_result_hosts; echo -n "End: "; date; | tee eyewitness_result_hosts.txt

echo -n "Start curl for hosts: "; date; while read -r HOST; do echo "HOST: $HOST"; curl --silent --head --location --insecure --verbose --user-agent "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:139.0) Gecko/20100101 Firefox/139.0" "$HOST" 2>&1; done < have_web_ports_open.txt; echo -n "End: "; date; | tee curl_result_hosts.txt;

cat curl_result* | grep -ivE "x-pingback|subdomain:|cn=|set-cookie|s.net|vary:|report-to:|location:|^\*|link:|HOST:|content-security-policy|DOMAIN:|HEAD \/|expires=|<|>" | grep -iE "apache|next|php|node|asp|microsoft|iis|httpapi|nginx|cerberus" | sort | uniq > web_backend_technology.txt

## SUMMARY

echo -e "\n\nWeb checks" >> $SUMMARY
echo -n "* Exposed technologies in headers: " >> $SUMMARY; grep "" web_backend_technology -c >> $SUMMARY;








######## HEADERS AND SSL CHECKS
echo -e "\n\n---- HEADERS AND SSL CHECKS ----";

cat have_web_ports_open.txt final_urls.txt > have_web.txt;

echo -n "Start sslscan: "; date; while read -r HOST; do sslscan --disable-ssl-check $HOST; done < have_web.txt; echo -n "End: "; date; | tee sslscan_result.txt;

FILE="shcheck_result.txt"; echo -n "Start shcheck: "; date; while read -r URL; do echo "URL: $URL"; shcheck "$URL"; done < have_web.txt; echo -n "End: "; date; | tee shcheck_result.txt;

## SUMMARY
echo -e "\n\nSSL/TLS checks" >> $SUMMARY;
echo -n "* Instances of outdated SSL/TLS versions: " >> $SUMMARY; cat sslscan_result* | grep -ivE "Accepted|Preferred|heartbleed|bits" | grep -iE "Testing|TLSv1.0|TLSv1.1|SSLv2|SSLv3|Subject" | grep -iE "enabled" -c >> $SUMMARY;
echo -n "* Instances of DES/3DES: " $SUMMARY; cat sslscan_result* | grep -ivE "SHA256|SHA384" | grep -iE "DES|3DES" -c >> $SUMMARY;







######## WORDPRESS CHECKS
echo -e "\n\n---- WORDPRESS CHECKS";
# /wp-json/
echo -n "Start curl for wp-json: "; date; while read -r DOMAIN; do echo "DOMAIN: $DOMAIN"; curl -sILk "https://$DOMAIN/wp-json/"; done < scope_domains.txt; echo -n "End: "; date; | tee curl_result_wp-json.txt;

# /wp-cron.php
echo -n "Start curl for wp-cron: "; date; while read -r DOMAIN; do echo "DOMAIN: $DOMAIN"; curl -sILk "https://$DOMAIN/wp-cron.php"; done < scope_domains.txt; echo -n "End: "; date; | tee curl_result_wp-cron.txt;

# /xmlrpc.php
echo -n "Start curl for xmlrpc: "; date; while read -r DOMAIN; do echo "DOMAIN: $DOMAIN"; curl -sILk "https://$DOMAIN/xmlrpc.php"; done < scope_domains.txt; echo -n "End: "; date; | tee curl_result_xmlrpc.txt;

# /wp-admin/install.php?step=1
echo -n "Start curl for install.php: "; date; while read -r DOMAIN; do echo "DOMAIN: $DOMAIN"; curl -sILk "https://$DOMAIN/wp-admin/install.php?step=1"; done < scope_domains.txt; echo -n "End: "; date; | tee curl_result_install.txt;

# /user
echo -n "Start wp/api/v2/users: "; date; while read -r DOMAIN; do echo "DOMAIN: $DOMAIN"; curl -sILk "https://$DOMAIN/wp/api/v2/users/"; done < scope_domains.txt; echo -n "End: "; date; | tee curl_result_users1.txt;
echo -n "Start wp-json/wp/v2/users: "; date; while read -r DOMAIN; do echo "DOMAIN: $DOMAIN"; curl -sILk "https://$DOMAIN/wp-json/wp/v2/users/"; done < scope_domains.txt; echo -n "End: "; date; | tee curl_result_users2.txt;
echo -n "Start author-sitemap.xml: "; date; while read -r DOMAIN; do echo "DOMAIN: $DOMAIN"; curl -sILk "https://$DOMAIN/author-sitemap.xml"; done < scope_domains.txt; echo -n "End: "; date; | tee curl_result_users3.txt;

## SUMMARY
echo -e "\nWordPress checks" >> $SUMMARY;
echo -e -n "* Instances with /wp-json (WordPress): " >> $SUMMARY; grep -iE "HTTP\/" curl_result_wp-json.txt | grep "200" -c >> $SUMMARY;
echo -e -n "\n* Instances with wp-cron.php: " >> $SUMMARY; grep "HTTP\/" curl_result_wp-cron.txtgrep -iE | grep "200" -c >> $SUMMARY;
echo -e -n "\n* Instances with xmlrpc.php: " >> $SUMMARY; grep -iE "HTTP\/" curl_result_xmlrpc.txt | grep "405" -c >> $SUMMARY;
echo -e -n "\n* Instances with install.php: " >> $SUMMARY; grep -iE "HTTP\/" curl_result_install.txt | grep "200" -c >> $SUMMARY;
echo -e -n "\n* Instances with /wp/api/v2/users/: " >> $SUMMARY; grep -iE "HTTP\/" curl_result_users1.txt | grep "200" -c >> $SUMMARY;
echo -e -n "\n* Instances with /wp-json/wp/v2/users/: " >> $SUMMARY; grep -iE "HTTP\/" curl_result_users2.txt | grep "200" -c -c >> $SUMMARY;
echo -e -n "\n* Instances with /author-sitemap.xml: " >> $SUMMARY; grep -iE "HTTP\/" curl_result_users3.txt | grep "200" -c >> $SUMMARY;







######## SUMMARY
cat $SUMMARY;
