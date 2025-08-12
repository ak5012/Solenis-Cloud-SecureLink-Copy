#!/bin/bash

set -e

reset

# Configuration
PYTHON_VERSION=3.11
VENV_DIR="/home/pi/tedge-venv"
METADATA_SCRIPT="/home/pi/send_revpi_metadata.sh"

# Detect if the device has one or two Ethernet interfaces
DUAL_ETH=false
ETH_INTERFACES=( $(ip -o link | awk -F': ' '/eth[0-9]/{print $2}') )
if [[ "${#ETH_INTERFACES[@]}" -ge 2 ]]; then
    DUAL_ETH=true
    echo "=== Multiple Network Interfaces ==="
    echo "=== eth0 (Port A): Local Area Network (Fixed IP)==="
    echo "=== eth1 (Port B): Wide Area Network (DHCP) ==="
    read -rp "Enter Fixed LAN IP Address (i.e. 192.168.1.1): " GATEWAY

    # Validate IP format
    if [[ ! $GATEWAY =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
      echo "Invalid IP address format."
      exit 1
    fi

    # Extract subnet (first three octets)
    SUBNET=$(echo "$GATEWAY" | awk -F. '{print $1"."$2"."$3}')

    # Generate DHCP range
    START_IP="${SUBNET}.100"
    END_IP="${SUBNET}.150"

fi

# Prompt user for Cumulocity-specific values
read -rp "Enter your Cumulocity tenant URL (e.g. dev1.iot-dev.solenis.com): " C8Y_URL
read -rp "Enter your Cumulocity Device ID: " DEVICE_ID
read -rp "Enter your Cumulocity One-Time Password: " DEVICE_ONE_TIME_PASSWORD

echo "=== Updating system packages ==="
sudo apt update && sudo apt upgrade -y

echo "=== Installing required packages ==="
sudo apt install -y \
    python${PYTHON_VERSION} \
    python${PYTHON_VERSION}-venv \
    python3-pip \
    mosquitto-clients \
    curl \
    ca-certificates \
    software-properties-common \
    cron \
    apt-transport-https \
    gnupg \
    gnupg2 \
    arp-scan \
    host \
    jq \
    cockpit-revpi-nodered \
    cockpit-pcp \
    snmp

echo "=== Creating Python virtual environment ==="
python${PYTHON_VERSION} -m venv "$VENV_DIR"
source "$VENV_DIR/bin/activate"

echo "=== Upgrade Python Pip ==="
# --- Upgrade pip ---
pip install --upgrade pip

echo "=== Installing Python Pip Packages ==="
# --- Install Python dependencies ---
pip install pymodbus==3.5.4 paho-mqtt requests

if [[ "$DUAL_ETH" == "true" ]]; then
  echo "=== Configuring network interfaces with NetworkManager ==="

  sudo apt install -y \
    network-manager \
    dnsmasq \
    iptables \
    iptables-persistent

  # Clean up old connections
  nmcli con delete eth0 || true
  nmcli con delete eth1 || true

  # Add eth0 static
  nmcli con add type ethernet ifname eth0 con-name eth0 ipv4.addresses "$GATEWAY"/24 ipv4.method manual

  # Add eth1 DHCP
  nmcli con add type ethernet ifname eth1 con-name eth1 ipv4.method auto

  # Bring them up
  nmcli con up eth0
  nmcli con up eth1

  echo "=== Setting up dnsmasq for DHCP on eth0 ==="

  sudo tee /etc/dnsmasq.d/eth0.conf >/dev/null <<EOF
interface=eth0
dhcp-range=${START_IP},${END_IP},12h
domain-needed
bogus-priv
EOF

  sudo systemctl enable dnsmasq
  sudo systemctl restart dnsmasq

  echo "=== Enabling IP forwarding ==="
  echo "net.ipv4.ip_forward=1" | sudo tee /etc/sysctl.d/99-ip-forward.conf
  sudo sysctl --system

  echo "=== Configuring iptables: NAT + Port Forwarding ==="

  # Clear existing rules
  sudo iptables -F
  sudo iptables -t nat -F

  # NAT: share internet from eth1 to eth0
  sudo iptables -t nat -A POSTROUTING -o eth1 -j MASQUERADE
  sudo iptables -A FORWARD -i eth0 -o eth1 -j ACCEPT
  sudo iptables -A FORWARD -i eth1 -o eth0 -m state --state ESTABLISHED,RELATED -j ACCEPT

  # Port forward: eth1:3080 to XXX.XXX.XXX.254:80
  #sudo iptables -t nat -A PREROUTING -i eth1 -p tcp --dport 3080 -j DNAT --to-destination "$SUBNET".254:80
  #sudo iptables -A FORWARD -p tcp -d "$SUBNET".254 --dport 80 -j ACCEPT

  # Port forward: eth1:3502 to XXX.XXX.XXX.254:502
  #sudo iptables -t nat -A PREROUTING -i eth1 -p tcp --dport 3502 -j DNAT --to-destination "$SUBNET".254:502
  #sudo iptables -A FORWARD -p tcp -d "$SUBNET".254 --dport 502 -j ACCEPT

  # Save iptables rules
  echo "=== Saving iptables rules persistently ==="
  sudo netfilter-persistent save
  sudo netfilter-persistent reload

  echo "RevPi network setup complete!"
  echo "eth0: Static LAN ($GATEWAY/24, DHCP)"
  echo "eth1: DHCP with internet"
  echo "NAT enabled eth0 to eth1"
  #echo "Port forwarding: eth1:3080 to 192.168.1.254:80"
  #echo "Port forwarding: eth1:3502 to 192.168.1.254:502"
fi

echo "=== Installing thin-edge.io via official install script ==="
curl -fsSL https://thin-edge.io/install.sh | sh -s


echo "=== Configuring tedge for Cumulocity ==="
sudo tedge config set c8y.url "$C8Y_URL"
sudo tedge cert download c8y --device-id "$DEVICE_ID" --one-time-password "$DEVICE_ONE_TIME_PASSWORD"

sudo tedge config set c8y.availability.interval 1m

echo "=== Connecting to Cumulocity ==="
sudo tedge connect c8y

echo "=== Installing thin-edge packages ==="
curl -1sLf 'https://dl.cloudsmith.io/public/thinedge/community/setup.deb.sh' | sudo -E bash
sudo apt install tedge-command-plugin

# Default to current user if none provided
TARGET_USER="${1:-$USER}"
CMD_PATH="$(command -v arp-scan)"

if [[ -z "$CMD_PATH" ]]; then
  echo "Error: arp-scan is not installed. Please install it first (e.g., sudo apt install arp-scan)."
  exit 1
fi

SUDOERS_FILE="/etc/sudoers.d/arp-scan-$TARGET_USER"

echo "Granting NOPASSWD access to '$CMD_PATH' for user '$TARGET_USER'..."

echo "$TARGET_USER ALL=(ALL) NOPASSWD: $CMD_PATH" | sudo tee "$SUDOERS_FILE" > /dev/null
sudo chmod 440 "$SUDOERS_FILE"

echo "Successfully created sudoers file: $SUDOERS_FILE"

echo "=== Setting up shared access to inventory file ==="
sudo groupadd -f tedge_shared
sudo usermod -aG tedge_shared pi
sudo usermod -aG tedge_shared tedge

echo "=== Creating metadata script ==="
cat <<'EOF' > "$METADATA_SCRIPT"
#!/bin/bash

set -e

cidr_to_netmask() {
  local cidr=$1
  if ! [[ "$cidr" =~ ^[0-9]+$ ]] || [ "$cidr" -lt 0 ] || [ "$cidr" -gt 32 ]; then
    echo ""
    return
  fi
  local i mask=""
  local full_octets=$((cidr / 8))
  local remaining_bits=$((cidr % 8))
  for ((i = 0; i < 4; i++)); do
    if [ $i -lt $full_octets ]; then
      mask+="255"
    elif [ $i -eq $full_octets ]; then
      mask+=$((256 - 2 ** (8 - remaining_bits)))
    else
      mask+="0"
    fi
    [ $i -lt 3 ] && mask+="."
  done
  echo "$mask"
}

get_ip_and_netmask() {
  local iface=$1
  local cidr_line
  cidr_line=$(ip addr show "$iface" | awk '/inet / {print $2}' | head -n1)
  if [[ -n "$cidr_line" ]]; then
    local ip="${cidr_line%/*}"
    local cidr="${cidr_line#*/}"
    local netmask
    netmask=$(cidr_to_netmask "$cidr")
    echo "$ip" "$netmask"
  else
    echo "" ""
  fi
}

scan_lan_devices() {
  local iface=$1
  local devices_json="[]"
  local output
  output=$(arp-scan --interface="$iface" --localnet --retry=1 --timeout=50 || true)

  declare -A seen
  while IFS= read -r line; do
    if [[ "$line" =~ ^([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)[[:space:]]+([[:xdigit:]:]{17})[[:space:]]+(.*) ]]; then
      ip="${BASH_REMATCH[1]}"
      mac="${BASH_REMATCH[2]}"
      vendor="${BASH_REMATCH[3]}"
      hostname=$(getent hosts "$ip" | awk '{print $2}' || echo "")
      if [[ -z "${seen[$mac]}" ]]; then
        seen["$mac"]=1
        device=$(cat <<EOD
{
  "ip": "$ip",
  "mac": "$mac",
  "hostname": "$hostname",
  "vendor": "$vendor",
  "type": "wired"
}
EOD
)
        devices_json=$(echo "$devices_json" | jq ". + [$device]")
      fi
    fi
  done <<< "$output"

  echo "$devices_json"
}

snmp_get_string() {
  local oid=$1
  local community="public"
  local gateway_ip
  gateway_ip=$(ip route | awk '/default/ {print $3}')
  if [ -z "$gateway_ip" ]; then
    echo ""
    return
  fi
  local result
  result=$(snmpget -v2c -c "$community" "$gateway_ip" "$oid" 2>/dev/null)
  if [[ $? -ne 0 || -z "$result" ]]; then
    echo ""
    return
  fi
  echo "$result" | awk -F': ' '{print $2}' | tr -d '"'
}

DEVICE_ID="$(hostname)"
SERIAL="$(grep Serial /proc/cpuinfo | awk '{print $3}')"
MODEL="$(cat /sys/firmware/devicetree/base/model | tr -d '\0')"
OS="$(uname -s)"
ARCH="$(uname -m)"
ETH0_MAC="$(ip link show eth0 | awk '/ether/ {print $2}')"
ETH1_MAC="$(ip link show eth1 | awk '/ether/ {print $2}')"
read ETH0_IP ETH0_NETMASK < <(get_ip_and_netmask eth0)
read ETH1_IP ETH1_NETMASK < <(get_ip_and_netmask eth1)
LAST_REBOOT=$(uptime -s | xargs -I {} date --utc +"%Y-%m-%dT%H:%M:%SZ" -d "{}")
METADATA_UPDATED=$(date --utc +"%Y-%m-%dT%H:%M:%SZ")

GATEWAY_SERIAL=$(snmp_get_string "iso.3.6.1.4.1.48690.1.1.0")
GATEWAY_MOBILE_IP=$(snmp_get_string "iso.3.6.1.4.1.48690.2.2.1.24.1")
GATEWAY_ICCID=$(snmp_get_string "iso.3.6.1.4.1.48690.2.2.1.27.1")
GATEWAY_MODEL=$(snmp_get_string "iso.3.6.1.4.1.48690.1.3.0")

if [[ -n "$GATEWAY_SERIAL" || -n "$GATEWAY_MOBILE_IP" || -n "$GATEWAY_ICCID" || -n "$GATEWAY_MODEL" ]]; then
  echo "Teltonika Gateway Present"
  WAN_JSON=$(cat <<EOF2
    "c8y_WAN": {
      "interface": "eth1",
      "mac": "$ETH1_MAC",
      "ip": "$ETH1_IP",
      "netmask": "$ETH1_NETMASK",
      "gatewaySerial": "$GATEWAY_SERIAL",
      "gatewayMobileIp": "$GATEWAY_MOBILE_IP",
      "gatewayIccid": "$GATEWAY_ICCID",
      "gatewayModel": "$GATEWAY_MODEL"
    }
EOF2
)
else
  WAN_JSON=$(cat <<EOF2
    "c8y_WAN": {
      "interface": "eth1",
      "mac": "$ETH1_MAC",
      "ip": "$ETH1_IP",
      "netmask": "$ETH1_NETMASK"
    }
EOF2
)
fi

WIFI_JSON=""
if ip link show wlan0 &>/dev/null; then
  WLAN_MAC="$(ip link show wlan0 | awk '/ether/ {print $2}')"
  SSID="$(iwgetid -r)"
  SSID_PASSWORD=""
  if [[ -n "$SSID" && -f "/etc/NetworkManager/system-connections/$SSID.nmconnection" ]]; then
    SSID_PASSWORD="$(sudo grep '^psk=' "/etc/NetworkManager/system-connections/$SSID.nmconnection" | cut -d= -f2)"
  fi
  WIFI_JSON=$(cat <<EOW
    ,
    "c8y_WLAN": {
      "ssid": "$SSID",
      "mac": "$WLAN_MAC",
      "ssidPassword": "$SSID_PASSWORD"
    }
EOW
)
else
  echo "Warning: wlan0 does not exist. Skipping Wi-Fi details in inventory."
fi

echo "Scanning devices on eth0..."
LAN_DEVICES=$(scan_lan_devices eth0)

TMP_FILE=$(mktemp)
cat <<EOF2 > "$TMP_FILE"
{
  "metadataUpdated": "$METADATA_UPDATED",
  "type": "SecureLink",
  "c8y_RequiredAvailability": {
    "responseInterval": 5
  },
  "c8y_Hardware": {
    "model": "$MODEL",
    "revision": "$ARCH",
    "serialNumber": "$SERIAL",
    "lastReboot": "$LAST_REBOOT"
  },
  "c8y_Network": {
    "c8y_LAN": {
      "interface": "eth0",
      "netmask": "$ETH0_NETMASK",
      "ip": "$ETH0_IP",
      "mac": "$ETH0_MAC",
      "devices": $LAN_DEVICES
    },
$WAN_JSON$WIFI_JSON
  }
}
EOF2

sudo mv "$TMP_FILE" /etc/tedge/device/inventory.json
sudo chown root:tedge_shared /etc/tedge/device/inventory.json
sudo chmod 664 /etc/tedge/device/inventory.json
echo "Inventory JSON written to /etc/tedge/device/inventory.json"
echo "Restarting tedge-mapper-c8y to publish updated inventory..."
sudo systemctl restart tedge-mapper-c8y
echo "Inventory update complete."
EOF

chmod +x "$METADATA_SCRIPT"

echo "=== Running initial metadata publish ==="
bash "$METADATA_SCRIPT"

echo "=== Adding cron jobs for metadata refresh ==="

# Define cron job lines (no sudo needed when running as user)
REBOOT_JOB="@reboot sleep 30 && bash $METADATA_SCRIPT /dev/null 2>&1 # Send C8Y Device Metadata after Reboot"
SCHEDULED_JOB="*/10 * * * * bash $METADATA_SCRIPT # Send C8Y Device Metadata every 10 minutes"

# Write new cron jobs to a temporary file
CRON_TEMP=$(mktemp)
echo "$REBOOT_JOB" >> "$CRON_TEMP"
echo "$SCHEDULED_JOB" >> "$CRON_TEMP"

# Install the new crontab for user 'pi'
sudo crontab -u pi "$CRON_TEMP"
rm "$CRON_TEMP"

echo "=== Setup complete! To activate your Python venv, run:"
echo "  source $VENV_DIR/bin/activate"
