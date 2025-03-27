# S.N.I.F.F. - "Security Network Inspection For Flaws"
Scripts (win/nix) that apply Wireshark filters to a .pcap file, and extract results from the command line.

WHY?
Speed.
No Dependencies: No Python, no libraries, no extra tools, no fuss - just what Wireshark gives you.
Automated: One script runs multiple filters, no manual clicking.
Simple: Outputs are raw packet summaries which are enough to spot issues, then jump back to Wireshark for details/further analysis.

Creates an output folder with a .txt file for each filter’s hits.
You should get all output files (like http_methods.txt, etc).
Empty files should flip to -empty suffixes (tells you at a glance which filters came up dry).
Check output\errors.log if any “WARNING” messages pop up.

.bat
Prep: Save as sniff.bat
Run: Drop your capture.pcap in the same folder and click, or drag your pcap it into the batch.
Path Fix: If tshark’s elsewhere (normally C:\Wireshark\tshark.exe), update the TSHARK path.

.sh
Prep: Save as sniff.sh, make executable with chmod +x sniff.sh.
Run: ./sniff.sh (with capture.pcap in the same dir).
Path Fix: If tshark’s not in PATH, update TSHARK="/path/to/tshark".
