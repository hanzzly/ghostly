#!/bin/bash
# install-ghost.sh

echo "[+] Installing Ghost Anonymous Mode..."

# Install dependencies
sudo apt update
sudo apt install -y tor proxychains macchanger privoxy curl

# Download main script
sudo wget -O /usr/local/bin/ghost https://raw.githubusercontent.com/user/repo/ghost.sh
sudo chmod +x /usr/local/bin/ghost

# Create config directory
sudo mkdir -p /etc/ghost

# Create aliases
echo 'alias ghost-on="sudo ghost on"' >> ~/.bashrc
echo 'alias ghost-off="sudo ghost off"' >> ~/.bashrc
echo 'alias ghost-status="ghost status"' >> ~/.bashrc

echo "[+] Installation complete!"
echo "[+] Usage:"
echo "    ghost-on     # Enable anonymous mode"
echo "    ghost-off    # Disable anonymous mode"
echo "    ghost-status # Check status"
