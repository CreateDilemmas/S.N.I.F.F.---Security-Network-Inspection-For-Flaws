#!/bin/bash

# SNIFF - Security Network Inspection For Flaws
# c9d0a14b43b0798dc41f057cdb02fe09

# Set tool paths
TSHARK="tshark"  # Assumes tshark is in PATH; update if needed (e.g., /usr/bin/tshark)

# Check if tools exist
if ! command -v "$TSHARK" &> /dev/null; then
    echo "ERROR: tshark not found. Install Wireshark or update the path."
    exit 1
fi

# Check for PCAP argument, default to capture.pcap if none provided
if [ -z "$1" ]; then
    PCAP="capture.pcap"
    echo "No PCAP file specified, defaulting to $PCAP"
else
    PCAP="$1"
fi

if [ ! -f "$PCAP" ]; then
    echo "ERROR: PCAP file '$PCAP' not found in current directory."
    exit 1
fi

mkdir -p output
TEMPFILE="output/temp.txt"

echo "Running filters on $PCAP..."

# Define specific filters
# Format: FILTER_NAME[index]="name" and FILTER_STRING[index]="filter"
declare -A FILTER_NAME
declare -A FILTER_STRING

FILTER_NAME[1]="http_requests"
FILTER_STRING[1]="http.request.method"
# Description: Catches plain HTTP requests (GET, POST, etc.) - unencrypted API calls or admin pages.

FILTER_NAME[2]="api_keys"
FILTER_STRING[2]="http contains \"api_key\" or http contains \"token\""
# Description: Looks for API keys or tokens in HTTP traffic - potential leaks.

FILTER_NAME[3]="errors"
FILTER_STRING[3]="http.response.code >= 400"
# Description: Finds HTTP errors (400s, 500s) - may leak stack traces or firmware versions.

FILTER_NAME[4]="weird_content"
FILTER_STRING[4]="http.content_type and not http.content_type contains \"json\" and not http.content_type contains \"html\""
# Description: Spots HTTP content types that aren’t JSON or HTML - possible debug endpoints.

FILTER_NAME[5]="telnet"
FILTER_STRING[5]="tcp.port == 23"
# Description: Detects telnet traffic - unencrypted remote access.

FILTER_NAME[6]="insecure_tls"
FILTER_STRING[6]="tls.handshake.version == 0x0300 or tls.handshake.version == 0x0301 or tls.handshake.version == 0x0302"
# Description: Flags TLS versions below 1.2 (SSLv3, TLS 1.0, TLS 1.1) - insecure encryption.

FILTER_NAME[7]="unencrypted"
FILTER_STRING[7]="tcp.port != 443 and tcp.port != 53 and not tls and not arp and not icmp"
# Description: Catches unencrypted TCP traffic (not HTTPS or DNS) excluding ARP/ICMP - potential plain-text leaks.

FILTER_NAME[8]="ftp"
FILTER_STRING[8]="ftp"
# Description: Flags FTP traffic - unencrypted file transfers.

FILTER_NAME[9]="insecure_ciphers"
# Define the list of insecure cipher suites (hex values from https://ciphersuite.info/cs/?security=insecure)
INSECURE_CIPHERS="0x0019 0x0017 0xC05A 0xC047 0xC05B 0x0046 0x00BF 0xC084 0x0089 0x00C5 0xC085 0x001A 0x001B 0x0018 0x009B 0x000B 0x000C 0x0011 0x0012 0x002D 0x00B4 0x00B5 0x008E 0x0034 0x0014 0x0015 0x000E 0x000F 0xC017 0xC018 0xC019 0xC015 0xC016 0xC001 0x006C 0xC002 0xC006 0xC007 0xC039 0xC03A 0xC03B 0xC033 0xC010 0xC011 0xC00B 0x00A6 0xC00C 0xC102 0xC100 0xC103 0xC105 0xC101 0xC104 0xC106 0x0029 0x0026 0x003A 0x002A 0x0027 0x002B 0x0028 0x0023 0x0022 0x006D 0x001E 0x0025 0x0024 0x0020 0x0000 0x002C 0x00B0 0x00B1 0x008A 0x00A7 0x0008 0x0006 0x0003 0x002E 0x00B8 0x00B9 0x0092 0x0009 0x0001 0x0002 0x003B 0x0004 0x0005 0xC0B4 0xC0B5 0x00C7 0x00C6 0xC046"
# Dynamically build the filter string for insecure cipher suites
FILTER_STRING[9]="("
FIRST=1
for c in $INSECURE_CIPHERS; do
    if [ $FIRST -eq 1 ]; then
        FILTER_STRING[9]="${FILTER_STRING[9]}tls.handshake.ciphersuite == $c"
        FIRST=0
    else
        FILTER_STRING[9]="${FILTER_STRING[9]} or tls.handshake.ciphersuite == $c"
    fi
done
FILTER_STRING[9]="${FILTER_STRING[9]})"
# Description: Finds any insecure cipher suites listed from https://ciphersuite.info/cs/?security=insecure

FILTER_COUNT=9

# Loop through all defined filters
for ((i=1; i<=FILTER_COUNT; i++)); do
    FILTER_NAME="${FILTER_NAME[$i]}"
    FILTER_STRING="${FILTER_STRING[$i]}"
    echo "Checking $FILTER_NAME..."
    [ -f "$TEMPFILE" ] && rm -f "$TEMPFILE"
    "$TSHARK" -r "$PCAP" -Y "$FILTER_STRING" > "$TEMPFILE" 2>>"output/errors.log"
    if [ $? -eq 0 ]; then
        if [ -s "$TEMPFILE" ]; then
            echo "Filter: $FILTER_STRING" > "output/$FILTER_NAME.txt"
            echo "--------------------------------" >> "output/$FILTER_NAME.txt"
            cat "$TEMPFILE" >> "output/$FILTER_NAME.txt"
        else
            echo "Filter: $FILTER_STRING" > "output/_empty_$FILTER_NAME.txt"
            echo "No hits found." >> "output/_empty_$FILTER_NAME.txt"
        fi
        rm -f "$TEMPFILE"
    else
        echo "WARNING: tshark failed on $FILTER_NAME - check errors.log"
    fi
done

# Special handling for dns_queries
echo "Checking dns_queries..."
[ -f "$TEMPFILE" ] && rm -f "$TEMPFILE"
"$TSHARK" -r "$PCAP" -Y "dns.qry.name" > "$TEMPFILE" 2>>"output/errors.log"
if [ $? -eq 0 ]; then
    if [ -s "$TEMPFILE" ]; then
        DNS_TOTAL=$(wc -l < "$TEMPFILE")
        if [ "$DNS_TOTAL" -gt 100 ]; then
            echo "Filter: dns.qry.name" > "output/dns_queries.txt"
            echo "--------------------------------" >> "output/dns_queries.txt"
            echo "Total DNS Queries: $DNS_TOTAL" >> "output/dns_queries.txt"
            echo "WARNING: Excessive DNS queries detected ($DNS_TOTAL > 100)" >> "output/dns_queries.txt"
            cat "$TEMPFILE" >> "output/dns_queries.txt"
        else
            echo "Filter: dns.qry.name" > "output/_empty_dns_queries.txt"
            echo "Total DNS Queries: $DNS_TOTAL - below threshold of 100" >> "output/_empty_dns_queries.txt"
        fi
        rm -f "$TEMPFILE"
    else
        echo "Filter: dns.qry.name" > "output/_empty_dns_queries.txt"
        echo "No DNS queries found." >> "output/_empty_dns_queries.txt"
    fi
else
    echo "WARNING: tshark failed on dns_queries - check errors.log"
fi

echo "Done! Check the 'output' folder for results."
