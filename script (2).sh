chmod +x framework.sh

# CVE mode — real request/response ratio per packet
./framework.sh cve --host 10.0.0.5 --port 61616 --total-packets 500

# Flood mode — Ctrl+C or Enter to stop
./framework.sh flood --host 10.0.0.5 --port 80 --workers 32 --conns 8

# Tor identity cycling
./framework.sh tor --tor-port 9050

# Reference factors
./framework.sh info
./framework.sh info --proto memcached
