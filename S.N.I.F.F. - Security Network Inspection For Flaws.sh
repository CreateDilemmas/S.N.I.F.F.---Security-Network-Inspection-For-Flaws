#!/bin/bash
# "SNIFF - Security Network Inspection For Flaws"
# Remember to chmod +x
# c9d0a14b43b0798dc41f057cdb02fe09
# Filter Descriptions:
# - "http.request.method": Catches plain HTTP requests (GET, POST, etc.) - unencrypted API calls or admin pages.
# - "http contains \"api_key\" or http contains \"token\"": Looks for API keys or tokens in HTTP traffic - potential leaks.
# - "http.response.code >= 400": Finds HTTP errors (400s, 500s) - may leak stack traces or firmware versions, etc.
# - "http.content_type and not http.content_type contains \"json\" and not http.content_type contains \"html\"": Spots HTTP content types that aren’t JSON or HTML - possible debug endpoints.
# - "tcp.port == 23": Detects telnet traffic - unencrypted remote access.
# - "tls.handshake.version == 0x0300 or tls.handshake.version == 0x0301 or tls.handshake.version == 0x0302": Flags TLS versions below 1.2 (SSLv3, TLS 1.0, TLS 1.1) - insecure encryption.
# - "tcp.port != 443 and tcp.port != 53 and not tls and not arp and not icmp": Catches unencrypted TCP traffic (not HTTPS or DNS) excluding ARP/ICMP - potential plain-text leaks.

# Set tool paths
TSHARK="tshark"  # Assumes tshark is in PATH; update if needed (e.g., /usr/bin/tshark)

# Check tools exist
if ! command -v "$TSHARK" &> /dev/null; then
    echo "ERROR: tshark not found. Install Wireshark or update the path."
    exit 1
fi

PCAP="capture.pcap"
if [ ! -f "$PCAP" ]; then
    echo "ERROR: $PCAP not found in current directory."
    exit 1
fi

mkdir -p output
TEMPFILE="output/temp.txt"

echo "Running filters..."

# Clean temp file if it exists
[ -f "$TEMPFILE" ] && rm -f "$TEMPFILE"

echo "Checking http.request.method..."
"$TSHARK" -r "$PCAP" -Y "http.request.method" > "$TEMPFILE" 2>> "output/errors.log"
if [ $? -eq 0 ]; then
    if [ -s "$TEMPFILE" ]; then
        echo "Filter: http.request.method" > "output/http_methods.txt"
        echo "--------------------------------" >> "output/http_methods.txt"
        cat "$TEMPFILE" >> "output/http_methods.txt"
    else
        echo "Filter: http.request.method" > "output/http_methods-empty.txt"
        echo "No hits found." >> "output/http_methods-empty.txt"
    fi
else
    echo "WARNING: tshark failed on http.request.method - check errors.log"
fi
[ -f "$TEMPFILE" ] && rm -f "$TEMPFILE"

echo "Checking api_keys..."
"$TSHARK" -r "$PCAP" -Y "http contains \"api_key\" or http contains \"token\"" > "$TEMPFILE" 2>> "output/errors.log"
if [ $? -eq 0 ]; then
    if [ -s "$TEMPFILE" ]; then
        echo "Filter: http contains \"api_key\" or http contains \"token\"" > "output/api_keys.txt"
        echo "--------------------------------" >> "output/api_keys.txt"
        cat "$TEMPFILE" >> "output/api_keys.txt"
    else
        echo "Filter: http contains \"api_key\" or http contains \"token\"" > "output/api_keys-empty.txt"
        echo "No hits found." >> "output/api_keys-empty.txt"
    fi
else
    echo "WARNING: tshark failed on api_keys - check errors.log"
fi
[ -f "$TEMPFILE" ] && rm -f "$TEMPFILE"

echo "Checking errors..."
"$TSHARK" -r "$PCAP" -Y "http.response.code >= 400" > "$TEMPFILE" 2>> "output/errors.log"
if [ $? -eq 0 ]; then
    if [ -s "$TEMPFILE" ]; then
        echo "Filter: http.response.code >= 400" > "output/errors.txt"
        echo "--------------------------------" >> "output/errors.txt"
        cat "$TEMPFILE" >> "output/errors.txt"
    else
        echo "Filter: http.response.code >= 400" > "output/errors-empty.txt"
        echo "No hits found." >> "output/errors-empty.txt"
    fi
else
    echo "WARNING: tshark failed on errors - check errors.log"
fi
[ -f "$TEMPFILE" ] && rm -f "$TEMPFILE"

echo "Checking weird_content..."
"$TSHARK" -r "$PCAP" -Y "http.content_type and not http.content_type contains \"json\" and not http.content_type contains \"html\"" > "$TEMPFILE" 2>> "output/errors.log"
if [ $? -eq 0 ]; then
    if [ -s "$TEMPFILE" ]; then
        echo "Filter: http.content_type and not http.content_type contains \"json\" and not http.content_type contains \"html\"" > "output/weird_content.txt"
        echo "--------------------------------" >> "output/weird_content.txt"
        cat "$TEMPFILE" >> "output/weird_content.txt"
    else
        echo "Filter: http.content_type and not http.content_type contains \"json\" and not http.content_type contains \"html\"" > "output/weird_content-empty.txt"
        echo "No hits found." >> "output/weird_content-empty.txt"
    fi
else
    echo "WARNING: tshark failed on weird_content - check errors.log"
fi
[ -f "$TEMPFILE" ] && rm -f "$TEMPFILE"

echo "Checking telnet..."
"$TSHARK" -r "$PCAP" -Y "tcp.port == 23" > "$TEMPFILE" 2>> "output/errors.log"
if [ $? -eq 0 ]; then
    if [ -s "$TEMPFILE" ]; then
        echo "Filter: tcp.port == 23" > "output/telnet.txt"
        echo "--------------------------------" >> "output/telnet.txt"
        cat "$TEMPFILE" >> "output/telnet.txt"
    else
        echo "Filter: tcp.port == 23" > "output/telnet-empty.txt"
        echo "No hits found." >> "output/telnet-empty.txt"
    fi
else
    echo "WARNING: tshark failed on telnet - check errors.log"
fi
[ -f "$TEMPFILE" ] && rm -f "$TEMPFILE"

echo "Checking insecure_tls..."
"$TSHARK" -r "$PCAP" -Y "tls.handshake.version == 0x0300 or tls.handshake.version == 0x0301 or tls.handshake.version == 0x0302" > "$TEMPFILE" 2>> "output/errors.log"
if [ $? -eq 0 ]; then
    if [ -s "$TEMPFILE" ]; then
        echo "Filter: tls.handshake.version == 0x0300 or tls.handshake.version == 0x0301 or tls.handshake.version == 0x0302" > "output/insecure_tls.txt"
        echo "--------------------------------" >> "output/insecure_tls.txt"
        cat "$TEMPFILE" >> "output/insecure_tls.txt"
    else
        echo "Filter: tls.handshake.version == 0x0300 or tls.handshake.version == 0x0301 or tls.handshake.version == 0x0302" > "output/insecure_tls-empty.txt"
        echo "No hits found." >> "output/insecure_tls-empty.txt"
    fi
else
    echo "WARNING: tshark failed on insecure_tls - check errors.log"
fi
[ -f "$TEMPFILE" ] && rm -f "$TEMPFILE"

echo "Checking unencrypted..."
"$TSHARK" -r "$PCAP" -Y "tcp.port != 443 and tcp.port != 53 and not tls and not arp and not icmp" > "$TEMPFILE" 2>> "output/errors.log"
if [ $? -eq 0 ]; then
    if [ -s "$TEMPFILE" ]; then
        echo "Filter: tcp.port != 443 and tcp.port != 53 and not tls and not arp and not icmp" > "output/unencrypted.txt"
        echo "--------------------------------" >> "output/unencrypted.txt"
        cat "$TEMPFILE" >> "output/unencrypted.txt"
    else
        echo "Filter: tcp.port != 443 and tcp.port != 53 and not tls and not arp and not icmp" > "output/unencrypted-empty.txt"
        echo "No hits found." >> "output/unencrypted-empty.txt"
    fi
else
    echo "WARNING: tshark failed on unencrypted - check errors.log"
fi
[ -f "$TEMPFILE" ] && rm -f "$TEMPFILE"

echo "Done! Check the 'output' folder for results."