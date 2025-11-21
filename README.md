# EXTERNAL-AID
A tool to perform subdomain enumeration, port scanning, dns configuration checks, SSL/TLS checks, screeshot of websites, and more.

## Usage
```bash
# It needs at least two files: 
#   scope_ips.txt: contains every IP, range, subnet ID to scan in a single line each
#   scope_domains.txt: contains every domain to target in a single line each
nano scope_ips.txt
nano scope_domains.txt

# To run it
./external-aid.sh
```

If you need to change your DNS resolution configuration:
```bash
sudo nano /etc/resolv.conf
```
Add or remove any DNS server you'd like