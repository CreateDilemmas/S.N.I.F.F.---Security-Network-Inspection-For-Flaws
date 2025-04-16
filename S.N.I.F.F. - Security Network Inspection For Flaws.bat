@echo off
setlocal enabledelayedexpansion
REM "SNIFF - Security Network Inspection For Flaws"
REM c9d0a14b43b0798dc41f057cdb02fe09

REM **Set tool paths**
set "TSHARK=C:\Program Files\Wireshark\tshark.exe"

REM **Check if tools exist**
if not exist "%TSHARK%" (
    echo ERROR: tshark not found at %TSHARK%. Update the path.
    pause
    exit /b 1
)

REM **Check for PCAP argument, default to capture.pcap if none provided**
if "%~1"=="" (
    set "PCAP=capture.pcap"
    echo No PCAP file specified, defaulting to %PCAP%
) else (
    set "PCAP=%~1"
)

if not exist "%PCAP%" (
    echo ERROR: PCAP file "%PCAP%" not found in current directory.
    pause
    exit /b 1
)

mkdir output 2>nul
set "TEMPFILE=output\temp.txt"

echo Running filters on %PCAP%...

REM **Define your specific filters here**
REM Format: set "FILTER<number>_NAME=<name>" and set "FILTER<number>_STRING=<filter>"

set "FILTER1_NAME=http_requests"
set "FILTER1_STRING=http.request.method"
REM Description: Catches plain HTTP requests (GET, POST, etc.) - unencrypted API calls or admin pages.

set "FILTER2_NAME=api_keys"
set "FILTER2_STRING=http contains \"api_key\" or http contains \"token\""
REM Description: Looks for API keys or tokens in HTTP traffic - potential leaks.

set "FILTER3_NAME=errors"
set "FILTER3_STRING=http.response.code >= 400"
REM Description: Finds HTTP errors (400s, 500s) - may leak stack traces or firmware versions.

set "FILTER4_NAME=weird_content"
set "FILTER4_STRING=http.content_type and not http.content_type contains \"json\" and not http.content_type contains \"html\""
REM Description: Spots HTTP content types that aren’t JSON or HTML - possible debug endpoints.

set "FILTER5_NAME=telnet"
set "FILTER5_STRING=tcp.port == 23"
REM Description: Detects telnet traffic - unencrypted remote access.

set "FILTER6_NAME=insecure_tls"
set "FILTER6_STRING=tls.handshake.version == 0x0300 or tls.handshake.version == 0x0301 or tls.handshake.version == 0x0302"
REM Description: Flags TLS versions below 1.2 (SSLv3, TLS 1.0, TLS 1.1) - insecure encryption.

set "FILTER7_NAME=unencrypted"
set "FILTER7_STRING=tcp.port ^!= 443 and tcp.port ^!= 53 and not tls and not arp and not icmp"
REM Description: Catches unencrypted TCP traffic (not HTTPS or DNS) excluding ARP/ICMP - potential plain-text leaks.

set "FILTER8_NAME=ftp"
set "FILTER8_STRING=ftp"
REM Description: Flags FTP traffic - unencrypted file tranfers.

set "FILTER9_NAME=insecure_ciphers"
REM Define the list of insecure cipher suites (hex values from https://ciphersuite.info/cs/?security=insecure)
set "INSECURE_CIPHERS=0x0019 0x0017 0xC05A 0xC047 0xC05B 0x0046 0x00BF 0xC084 0x0089 0x00C5 0xC085 0x001A 0x001B 0x0018 0x009B 0x000B 0x000C 0x0011 0x0012 0x002D 0x00B4 0x00B5 0x008E 0x0034 0x0014 0x0015 0x000E 0x000F 0xC017 0xC018 0xC019 0xC015 0xC016 0xC001 0x006C 0xC002 0xC006 0xC007 0xC039 0xC03A 0xC03B 0xC033 0xC010 0xC011 0xC00B 0x00A6 0xC00C 0xC102 0xC100 0xC103 0xC105 0xC101 0xC104 0xC106 0x0029 0x0026 0x003A 0x002A 0x0027 0x002B 0x0028 0x0023 0x0022 0x006D 0x001E 0x0025 0x0024 0x0020 0x0000 0x002C 0x00B0 0x00B1 0x008A 0x00A7 0x0008 0x0006 0x0003 0x002E 0x00B8 0x00B9 0x0092 0x0009 0x0001 0x0002 0x003B 0x0004 0x0005 0xC0B4 0xC0B5 0x00C7 0x00C6 0xC046"
REM Dynamically build the filter string for insecure cipher suites
set "FILTER9_STRING=("
set "FIRST=1"
for %%c in (%INSECURE_CIPHERS%) do (
    if !FIRST!==1 (
        set "FILTER9_STRING=!FILTER9_STRING!tls.handshake.ciphersuite == %%c"
        set "FIRST=0"
    ) else (
        set "FILTER9_STRING=!FILTER9_STRING! or tls.handshake.ciphersuite == %%c"
    )
)
set "FILTER9_STRING=!FILTER9_STRING!)"
REM Description: Finds any insecure cipher suites listed from https://ciphersuite.info/cs/?security=insecure

set "FILTER_COUNT=9"

REM **Loop through all defined filters**
for /l %%i in (1,1,%FILTER_COUNT%) do (
    set "FILTER_NAME=!FILTER%%i_NAME!"
    set "FILTER_STRING=!FILTER%%i_STRING!"
    echo Checking !FILTER_NAME!...
    if exist %TEMPFILE% del %TEMPFILE% >nul 2>&1
    "%TSHARK%" -r "%PCAP%" -Y "!FILTER_STRING!" > %TEMPFILE% 2>>output\errors.log
    if !ERRORLEVEL! equ 0 (
        if exist %TEMPFILE% (
            for %%f in (%TEMPFILE%) do if %%~zf GTR 0 (
                echo Filter: !FILTER_STRING! > output\!FILTER_NAME!.txt
                echo -------------------------------- >> output\!FILTER_NAME!.txt
                type %TEMPFILE% >> output\!FILTER_NAME!.txt
            ) else (
                echo Filter: !FILTER_STRING! > output\_empty_!FILTER_NAME!.txt
                echo No hits found. >> output\_empty_!FILTER_NAME!.txt
            )
            del %TEMPFILE% >nul 2>&1
        ) else (
            echo WARNING: Temp file not created for !FILTER_NAME! - check errors.log
        )
    ) else (
        echo WARNING: tshark failed on !FILTER_NAME! - check errors.log
    )
)

REM **Special handling for dns_queries**
echo Checking dns_queries...
if exist %TEMPFILE% del %TEMPFILE% >nul 2>&1
"%TSHARK%" -r "%PCAP%" -Y "dns.qry.name" > %TEMPFILE% 2>>output\errors.log
if %ERRORLEVEL% equ 0 (
    if exist %TEMPFILE% (
        for /f "tokens=2" %%i in ('find /c /v "" ^< %TEMPFILE%') do set DNS_TOTAL=%%i
        if !DNS_TOTAL! GTR 100 (
            echo Filter: dns.qry.name > output\dns_queries.txt
            echo -------------------------------- >> output\dns_queries.txt
            echo Total DNS Queries: !DNS_TOTAL! >> output\dns_queries.txt
            echo WARNING: Excessive DNS queries detected ^(!DNS_TOTAL! ^> 100^) >> output\dns_queries.txt
            type %TEMPFILE% >> output\dns_queries.txt
        ) else (
            echo Filter: dns.qry.name > output\_empty_dns_queries.txt
            echo Total DNS Queries: !DNS_TOTAL! - below threshold of 100 >> output\_empty_dns_queries.txt
        )
        del %TEMPFILE% >nul 2>&1
    ) else (
        echo Filter: dns.qry.name > output\_empty_dns_queries.txt
        echo No DNS queries found. >> output\_empty_dns_queries.txt
    )
) else (
    echo WARNING: tshark failed on dns_queries - check errors.log
)

echo Done! Check the 'output' folder for results.
pause
endlocal
