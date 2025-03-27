@echo off
REM "SNIFF - Security Network Inspection For Flaws"
REM c9d0a14b43b0798dc41f057cdb02fe09
REM Filter Descriptions:
REM - "http.request.method": Catches plain HTTP requests (GET, POST, etc.) - unencrypted API calls or admin pages.
REM - "http contains \"api_key\" or http contains \"token\"": Looks for API keys or tokens in HTTP traffic - potential leaks.
REM - "http.response.code >= 400": Finds HTTP errors (400s, 500s) - may leak stack traces or firmware versions, etc.
REM - "http.content_type and not http.content_type contains \"json\" and not http.content_type contains \"html\"": Spots HTTP content types that aren’t JSON or HTML - possible debug endpoints.
REM - "tcp.port == 23": Detects telnet traffic - unencrypted remote access.
REM - "tls.handshake.version < 0x0303": Flags TLS versions below 1.2 - insecure encryption.
REM - "tcp.port != 443 and tcp.port != 53 and not tls and not arp and not icmp": Catches unencrypted TCP traffic (not HTTPS or DNS) excluding ARP/ICMP - potential plain-text leaks.

REM Set tool paths
set "TSHARK=C:\Program Files\Wireshark\tshark.exe"

REM Check tools exist
if not exist "%TSHARK%" (
    echo ERROR: tshark not found at %TSHARK%. Update the path.
    pause
    exit /b 1
)

set PCAP=capture.pcap
if not exist "%PCAP%" (
    echo ERROR: %PCAP% not found in current directory.
    pause
    exit /b 1
)

mkdir output 2>nul
set TEMPFILE=output\temp.txt

echo Running filters...

REM Clean temp file if it exists
if exist %TEMPFILE% del %TEMPFILE% >nul 2>&1

echo Checking http.request.method...
if exist %TEMPFILE% del %TEMPFILE% >nul 2>&1
"%TSHARK%" -r %PCAP% -Y "http.request.method" > %TEMPFILE% 2>>output\errors.log
if %ERRORLEVEL% equ 0 (
    if exist %TEMPFILE% (
        for %%f in (%TEMPFILE%) do if %%~zf GTR 0 (
            echo Filter: http.request.method > output\http_methods.txt
            echo -------------------------------- >> output\http_methods.txt
            type %TEMPFILE% >> output\http_methods.txt
        ) else (
            echo Filter: http.request.method > output\http_methods-empty.txt
            echo No hits found. >> output\http_methods-empty.txt
        )
        del %TEMPFILE% >nul 2>&1
    ) else (
        echo WARNING: Temp file not created for http.request.method - check errors.log
    )
) else (
    echo WARNING: tshark failed on http.request.method - check errors.log
)

echo Checking api_keys...
if exist %TEMPFILE% del %TEMPFILE% >nul 2>&1
"%TSHARK%" -r %PCAP% -Y "http contains \"api_key\" or http contains \"token\"" > %TEMPFILE% 2>>output\errors.log
if %ERRORLEVEL% equ 0 (
    if exist %TEMPFILE% (
        for %%f in (%TEMPFILE%) do if %%~zf GTR 0 (
            echo Filter: http contains "api_key" or http contains "token" > output\api_keys.txt
            echo -------------------------------- >> output\api_keys.txt
            type %TEMPFILE% >> output\api_keys.txt
        ) else (
            echo Filter: http contains "api_key" or http contains "token" > output\api_keys-empty.txt
            echo No hits found. >> output\api_keys-empty.txt
        )
        del %TEMPFILE% >nul 2>&1
    ) else (
        echo WARNING: Temp file not created for api_keys - check errors.log
    )
) else (
    echo WARNING: tshark failed on api_keys - check errors.log
)

echo Checking errors...
if exist %TEMPFILE% del %TEMPFILE% >nul 2>&1
"%TSHARK%" -r %PCAP% -Y "http.response.code >= 400" > %TEMPFILE% 2>>output\errors.log
if %ERRORLEVEL% equ 0 (
    if exist %TEMPFILE% (
        for %%f in (%TEMPFILE%) do if %%~zf GTR 0 (
            echo Filter: http.response.code >= 400 > output\errors.txt
            echo -------------------------------- >> output\errors.txt
            type %TEMPFILE% >> output\errors.txt
        ) else (
            echo Filter: http.response.code >= 400 > output\errors-empty.txt
            echo No hits found. >> output\errors-empty.txt
        )
        del %TEMPFILE% >nul 2>&1
    ) else (
        echo WARNING: Temp file not created for errors - check errors.log
    )
) else (
    echo WARNING: tshark failed on errors - check errors.log
)

echo Checking weird_content...
if exist %TEMPFILE% del %TEMPFILE% >nul 2>&1
"%TSHARK%" -r %PCAP% -Y "http.content_type and not http.content_type contains \"json\" and not http.content_type contains \"html\"" > %TEMPFILE% 2>>output\errors.log
if %ERRORLEVEL% equ 0 (
    if exist %TEMPFILE% (
        for %%f in (%TEMPFILE%) do if %%~zf GTR 0 (
            echo Filter: http.content_type and not http.content_type contains "json" and not http.content_type contains "html" > output\weird_content.txt
            echo -------------------------------- >> output\weird_content.txt
            type %TEMPFILE% >> output\weird_content.txt
        ) else (
            echo Filter: http.content_type and not http.content_type contains "json" and not http.content_type contains "html" > output\weird_content-empty.txt
            echo No hits found. >> output\weird_content-empty.txt
        )
        del %TEMPFILE% >nul 2>&1
    ) else (
        echo WARNING: Temp file not created for weird_content - check errors.log
    )
) else (
    echo WARNING: tshark failed on weird_content - check errors.log
)

echo Checking telnet...
if exist %TEMPFILE% del %TEMPFILE% >nul 2>&1
"%TSHARK%" -r %PCAP% -Y "tcp.port == 23" > %TEMPFILE% 2>>output\errors.log
if %ERRORLEVEL% equ 0 (
    if exist %TEMPFILE% (
        for %%f in (%TEMPFILE%) do if %%~zf GTR 0 (
            echo Filter: tcp.port == 23 > output\telnet.txt
            echo -------------------------------- >> output\telnet.txt
            type %TEMPFILE% >> output\telnet.txt
        ) else (
            echo Filter: tcp.port == 23 > output\telnet-empty.txt
            echo No hits found. >> output\telnet-empty.txt
        )
        del %TEMPFILE% >nul 2>&1
    ) else (
        echo WARNING: Temp file not created for telnet - check errors.log
    )
) else (
    echo WARNING: tshark failed on telnet - check errors.log
)

echo Checking insecure_tls...
if exist %TEMPFILE% del %TEMPFILE% >nul 2>&1
"%TSHARK%" -r %PCAP% -Y "tls.handshake.version == 0x0300 or tls.handshake.version == 0x0301 or tls.handshake.version == 0x0302" > %TEMPFILE% 2>>output\errors.log
if %ERRORLEVEL% equ 0 (
    if exist %TEMPFILE% (
        for %%f in (%TEMPFILE%) do if %%~zf GTR 0 (
            echo Filter: tls.handshake.version == 0x0300 or tls.handshake.version == 0x0301 or tls.handshake.version == 0x0302 > output\insecure_tls.txt
            echo -------------------------------- >> output\insecure_tls.txt
            type %TEMPFILE% >> output\insecure_tls.txt
        ) else (
            echo Filter: tls.handshake.version == 0x0300 or tls.handshake.version == 0x0301 or tls.handshake.version == 0x0302 > output\insecure_tls-empty.txt
            echo No hits found. >> output\insecure_tls-empty.txt
        )
        del %TEMPFILE% >nul 2>&1
    ) else (
        echo WARNING: Temp file not created for insecure_tls - check errors.log
    )
) else (
    echo WARNING: tshark failed on insecure_tls - check errors.log
)

echo Checking unencrypted...
if exist %TEMPFILE% del %TEMPFILE% >nul 2>&1
"%TSHARK%" -r %PCAP% -Y "tcp.port != 443 and tcp.port != 53 and not tls and not arp and not icmp" > %TEMPFILE% 2>>output\errors.log
if %ERRORLEVEL% equ 0 (
    if exist %TEMPFILE% (
        for %%f in (%TEMPFILE%) do if %%~zf GTR 0 (
            echo Filter: tcp.port != 443 and tcp.port != 53 and not tls and not arp and not icmp > output\unencrypted.txt
            echo -------------------------------- >> output\unencrypted.txt
            type %TEMPFILE% >> output\unencrypted.txt
        ) else (
            echo Filter: tcp.port != 443 and tcp.port != 53 and not tls and not arp and not icmp > output\unencrypted-empty.txt
            echo No hits found. >> output\unencrypted-empty.txt
        )
        del %TEMPFILE% >nul 2>&1
    ) else (
        echo WARNING: Temp file not created for unencrypted - check errors.log
    )
) else (
    echo WARNING: tshark failed on unencrypted - check errors.log
)

echo Done! Check the 'output' folder for results.
pause