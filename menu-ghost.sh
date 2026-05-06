#!/bin/bash
# menu-ghost.sh - Interactive Menu

show_menu() {
    clear
    echo "╔══════════════════════════════════════╗"
    echo "║       GHOST ANONYMOUS MODE          ║"
    echo "╠══════════════════════════════════════╣"
    echo "║ 1. Enable Anonymous Mode            ║"
    echo "║ 2. Disable Anonymous Mode           ║"
    echo "║ 3. Check Current Status             ║"
    echo "║ 4. Test Anonymity                   ║"
    echo "║ 5. Quick IP Check                   ║"
    echo "║ 6. Install Tools                    ║"
    echo "║ 7. Exit                             ║"
    echo "╚══════════════════════════════════════╝"
    echo
    read -p "Select option [1-7]: " choice
}

enable_ghost() {
    echo "[+] Starting Tor..."
    sudo systemctl start tor
    sleep 2

    echo "[+] Changing MAC address..."
    sudo macchanger -r eth0 2>/dev/null

    echo "[+] Setting up proxy..."
    export http_proxy="socks5://127.0.0.1:9050"
    export https_proxy="socks5://127.0.0.1:9050"

    echo "[+] Anonymous mode ENABLED"
    read -n 1 -s -r -p "Press any key to continue..."
}

disable_ghost() {
    echo "[+] Stopping Tor..."
    sudo systemctl stop tor

    echo "[+] Resetting MAC..."
    sudo macchanger -p eth0 2>/dev/null

    echo "[+] Clearing proxy..."
    unset http_proxy https_proxy

    echo "[+] Anonymous mode DISABLED"
    read -n 1 -s -r -p "Press any key to continue..."
}

check_status() {
    echo "=== SYSTEM STATUS ==="

    # Check Tor
    if sudo systemctl is-active tor >/dev/null; then
        echo "Tor: RUNNING"
    else
        echo "Tor: STOPPED"
    fi

    # Check IP
    echo -n "Public IP: "
    curl --socks5 127.0.0.1:9050 -s https://ipinfo.io/ip 2>/dev/null || curl -s https://ipinfo.io/ip

    # Check MAC
    echo -n "MAC Address: "
    cat /sys/class/net/eth0/address 2>/dev/null || echo "N/A"

    read -n 1 -s -r -p "Press any key to continue..."
}

while true; do
    show_menu

    case $choice in
        1) enable_ghost ;;
        2) disable_ghost ;;
        3) check_status ;;
        4)
            echo "[+] Testing anonymity..."
            curl --socks5 127.0.0.1:9050 -s https://check.torproject.org | grep -q "Congratulations" && echo "✓ Using Tor" || echo "✗ Not using Tor"
            read -n 1 -s -r -p "Press any key to continue..."
            ;;
        5)
            echo -n "[+] Your IP: "
            curl --socks5 127.0.0.1:9050 -s https://ipinfo.io/ip 2>/dev/null || curl -s https://ipinfo.io/ip
            echo
            read -n 1 -s -r -p "Press any key to continue..."
            ;;
        6)
            echo "[+] Installing tools..."
            sudo apt update && sudo apt install -y tor proxychains macchanger
            echo "[+] Tools installed!"
            read -n 1 -s -r -p "Press any key to continue..."
            ;;
        7)
            echo "[+] Exiting..."
            exit 0
            ;;
        *)
            echo "[!] Invalid option"
            sleep 1
            ;;
    esac
done
