#!/bin/bash

set -e

reset

# Configuration
PYTHON_VERSION=3.11
VENV_DIR="/home/pi/tedge-venv"
GPAM_LIVE_SCRIPT="/home/pi/gpam_live.py"
GPAM_LIVE_CONFIG_JSON="/etc/tedge/plugins/config_gpam_live.json"
GPAM_LIVE_SERVICE_FILE="/etc/systemd/system/c8y-gpam-live.service"
GPAM_BATCH_SCRIPT="/home/pi/gpam_batch.py"
GPAM_BATCH_CONFIG_JSON="/etc/tedge/plugins/config_gpam_batch.json"
GPAM_BATCH_SERVICE_FILE="/etc/systemd/system/c8y-gpam-batch.service"
GPAM_ALARM_SCRIPT="/home/pi/gpam_alarm.py"
GPAM_ALARM_CONFIG_JSON="/etc/tedge/plugins/config_gpam_alarm.json"
GPAM_ALARM_SERVICE_FILE="/etc/systemd/system/c8y-gpam-alarm.service"
TEDGE_LOG_PLUGIN="/etc/tedge/plugins/tedge-log-plugin.toml"
TEDGE_CONFIG_PLUGIN="/etc/tedge/plugins/tedge-configuration-plugin.toml"

sudo apt update -y && sudo apt install tedge-log-plugin

echo "=== Creating Python virtual environment ==="
python${PYTHON_VERSION} -m venv "$VENV_DIR"
source "$VENV_DIR/bin/activate"

echo "=== Upgrade Python Pip ==="
# --- Upgrade pip ---
pip install --upgrade pip

echo "=== Installing Python Pip Packages ==="
# --- Install Python dependencies ---
pip install pycomm3

echo "=== Installing Python Configuration JSON for GPAM Live Data ==="
# --- Write Python script ---
cat > "$GPAM_LIVE_CONFIG_JSON" << 'EOF'
{
  "plc_ip": "192.168.1.52",
  "poll_interval": 60,
  "fragment": "GPAM",
  "registers": {
    "Live_Base_Temperature": {
      "tag": "F8:10",
      "unit": "C",
      "round": 0
    },
    "Live_CPAM_Bulk_Level": {
      "tag": "F8:13",
      "unit": "%",
      "round": 2
    },
    "Live_Critical_Faults": {
      "tag": "B3:1/1",
      "unit": "bool"
    },
    "Live_EStop_Button": {
      "tag": "B3:0/4",
      "unit": "bool"
    },
    "Live_Glyoal_Storage_Level": {
      "tag": "F8:14",
      "unit": "%",
      "round": 2
    },
    "Live_GPAM_Bulk_Level": {
      "tag": "F8:12",
      "unit": "%",
      "round": 2
    },
    "Live_Tank4_Bulk_Level": {
      "tag": "F8:0",
      "unit": "%",
      "round": 2
    },
    "Live_pH": {
      "tag": "F8:144",
      "round": 2
    },
    "Live_Reaction_Tank_Level": {
      "tag": "F8:3",
      "unit": "%",
      "round": 2
    },
    "Live_Reaction_Tank_Weight": {
      "tag": "F8:5",
      "unit": "kg",
      "round": 1
    },
    "Live_Recirc_Pump_Discharge_Pressure": {
      "tag": "F8:2",
      "unit": "psi",
      "round": 2
    },
    "Live_Run_Circ_Pump": {
      "tag": "B3:1/7",
      "unit": "bool"
    },
    "Live_Run_Water_Pump": {
      "tag": "B3:1/8",
      "unit": "bool"
    },
    "Live_Tank_Agitator": {
      "tag": "B3:1/6",
      "unit": "bool"
    },
    "Live_Sequence_Position": {
      "tag": "B3:1/6",
      "unit": "bool"
    },
    "Live_Tank_Turbidity": {
      "tag": "F12:5",
      "unit": "NTU",
      "round": 2
    },
    "Live_Water_Header_Pressure": {
      "tag": "F8:1",
      "unit": "psi",
      "round": 2
    },
    "Live_Batch_Number": {
      "tag": "F11:17"
    },
    "Live_Batch_Water_Added": {
      "tag": "F11:10",
      "unit": "kg",
      "round": 0
    },
    "Live_Batch_CPAM_Added": {
      "tag": "F11:11",
      "unit": "kg",
      "round": 0
    },
    "Live_Batch_Glyoxyl_Added": {
      "tag": "F11:12",
      "unit": "kg",
      "round": 0
    },
    "Live_Batch_Caustic_Water_Added": {
      "tag": "F11:13",
      "unit": "kg",
      "round": 0
    },
    "Live_Batch_Acid_Water_Added": {
      "tag": "F11:14",
      "unit": "kg",
      "round": 0
    },
    "Live_Batch_Relative_Turbidity_Change": {
      "tag": "F11:15",
      "unit": "NTU",
      "round": 1
    },
    "Live_Batch_Reaction_Time": {
      "tag": "F11:18",
      "unit": "sec",
      "round": 0
    },
    "Live_Turbidity_LoopFlow": {
      "tag": "F8:4",
      "unit": "lpm",
      "round": 2
    }
  }
}

EOF

sudo chown tedge:tedge "$GPAM_LIVE_CONFIG_JSON"

chmod +x "$GPAM_LIVE_CONFIG_JSON"

# --- Add Log Access to tedge ---
sudo tee -a "$TEDGE_CONFIG_PLUGIN" >/dev/null <<EOF

[[files]]
path = "${GPAM_LIVE_CONFIG_JSON}"
type = "config_gpam_live.json"

EOF

echo "=== Installing GPAM Live Data Python Script ==="
# --- Write Python script ---
cat > "$GPAM_LIVE_SCRIPT" << EOF

import json
import time
import argparse
from datetime import datetime, timezone
import subprocess
from pycomm3 import SLCDriver

CONFIG_FILE = '$GPAM_LIVE_CONFIG_JSON'
TOPIC = 'c8y/measurement/measurements/create'

def load_config(path):
    with open(path, 'r') as f:
        return json.load(f)

def get_timestamp():
    return datetime.now(timezone.utc).isoformat(timespec='seconds').replace('+00:00', 'Z')

def build_payload(fragment, timestamp, measurements):
    return json.dumps({
        "time": timestamp,
        "type": fragment,
        fragment: measurements
    })

def publish_to_c8y(payload, verbose):
    try:
        subprocess.run(['tedge', 'mqtt', 'pub', TOPIC, payload], check=True)
        if verbose:
            print(f"Published to {TOPIC}: {payload}")
    except subprocess.CalledProcessError as e:
        print(f"MQTT publish failed: {e}")

def poll_plc(config, verbose):
    ip = config['plc_ip']
    registers = config['registers']
    fragment = config.get('fragment', 'PLC')
    timestamp = get_timestamp()
    measurements = {}

    with SLCDriver(ip) as plc:
        for series, meta in registers.items():
            if str(meta.get("c8y_ignore", "false")).lower() == "true":
                continue

            tag = meta.get("tag")
            if not tag:
                continue

            result = plc.read(tag)
            if result is None:
                continue

            value = result.value
            if isinstance(value, bool):
                value = int(value)

            # Ensure value is numeric before rounding
            try:
                value = float(value)
            except (TypeError, ValueError):
                continue

            # Apply rounding if specified
            rounding = meta.get("round")
            if rounding is not None:
                try:
                    value = round(value, int(rounding))
                except Exception:
                    pass

            entry = {"value": value}
            if "unit" in meta:
                entry["unit"] = meta["unit"]

            measurements[series] = entry

            if verbose:
                print(f"{series}: {value} {meta.get('unit', '')}")

    if measurements:
        payload = build_payload(fragment, timestamp, measurements)
        publish_to_c8y(payload, verbose)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--print', dest='verbose', action='store_true', help='Print output to console')
    args = parser.parse_args()

    config = load_config(CONFIG_FILE)
    interval = int(config.get("poll_interval", 30))
    last_trigger_time = None

    if args.verbose:
        print(f"Monitoring system time for poll every {interval} seconds...")

    while True:
        now = datetime.now()
        total_seconds = now.minute * 60 + now.second

        if total_seconds % interval == 0:
            if last_trigger_time != total_seconds:
                last_trigger_time = total_seconds
                poll_plc(config, args.verbose)

        time.sleep(0.5)

if __name__ == "__main__":
    main()

EOF

chmod +x "$GPAM_LIVE_SCRIPT"

echo "=== Installing Python Configuration JSON for GPAM Batch Data ==="
# --- Write Python script ---
cat > "$GPAM_BATCH_CONFIG_JSON" << 'EOF'
{
  "plc_ip": "192.168.1.52",
  "fragment": "GPAM",
  "registers": {
    "Batch_End": {
      "tag": "B3:2/7",
      "c8y_ignore":"true"
    },
    "Batch_Acid_Water_Added": {
      "tag": "F11:14",
      "unit": "kg",
      "round": 0
    },
    "Batch_Number": {
      "tag": "F11:17"
    },
    "Batch_Caustic_Water_Added": {
      "tag": "F11:13",
      "unit": "kg",
      "round": 0
    },
    "Batch_CPAM_Added": {
      "tag": "F11:11",
      "unit": "kg",
      "round": 0
    },
    "Batch_Glyoxyl_Added": {
      "tag": "F11:12",
      "unit": "kg",
      "round": 0
    },
    "Batch_Reaction_Time": {
      "tag": "F11:18",
      "unit": "sec",
      "round": 0
    },
    "Batch_Relative_Turbidity_Change": {
      "tag": "F11:15",
      "unit": "NTU",
      "round": 1
    },
    "Batch_Water_Added": {
      "tag": "F11:10",
      "unit": "kg",
      "round": 0
    }
  }
}

EOF

sudo chown tedge:tedge "$GPAM_BATCH_CONFIG_JSON"

chmod +x "$GPAM_BATCH_CONFIG_JSON"

# --- Add Log Access to tedge ---
sudo tee -a "$TEDGE_CONFIG_PLUGIN" >/dev/null <<EOF
[[files]]
path = "${GPAM_BATCH_CONFIG_JSON}"
type = "config_gpam_batch.json"

EOF

echo "=== Installing GPAM Batch Data Python Script ==="
# --- Write Python script ---
cat > "$GPAM_BATCH_SCRIPT" << EOF
import json
import subprocess
import time
from datetime import datetime, timezone
from pycomm3 import SLCDriver

CONFIG_FILE = '$GPAM_BATCH_CONFIG_JSON'
BATCH_END = 'Batch_End'
BATCH_NUMBER = 'Batch_Number'
BATCH_REACTION_TIME = 'Batch_Reaction_Time'

def load_config(path):
    with open(path, 'r') as f:
        return json.load(f)

def get_iso8601_timestamp():
    return datetime.now(timezone.utc).isoformat(timespec='seconds').replace('+00:00', 'Z')

def build_payload(fragment, measurements, timestamp):
    return json.dumps({
        "time": timestamp,
        "type": fragment,
        fragment: measurements
    })

def publish_measurements(payload):
    topic = 'c8y/measurement/measurements/create'
    cmd = ['tedge', 'mqtt', 'pub', topic, payload]
    try:
        subprocess.run(cmd, check=True)
        print(payload)
    except subprocess.CalledProcessError as e:
        print(f"Failed to publish measurement: {e}")

def read_plc_and_post_if_triggered(config, previous_state):
    plc_ip = config["plc_ip"]
    fragment = config.get("fragment", "plc_data")
    registers = config["registers"]
    timestamp = get_iso8601_timestamp()

    batch_end_tag = registers.get(BATCH_END, {}).get("tag")
    batch_num_tag = registers.get(BATCH_NUMBER, {}).get("tag")

    with SLCDriver(plc_ip) as plc:
        batch_end_result = plc.read(batch_end_tag) if batch_end_tag else None
        batch_num_result = plc.read(batch_num_tag) if batch_num_tag else None

        if batch_end_result is None or batch_num_result is None:
            print("Failed to read Batch_End or Batch_Number.")
            return previous_state

        batch_end_current = bool(batch_end_result.value)
        batch_number_current = batch_num_result.value

        # Trigger if Batch_End is true and either rising edge or batch number changed
        should_poll = False
        if batch_end_current:
            if not previous_state["batch_end"]:
                should_poll = True
            elif batch_number_current != previous_state["batch_number"]:
                should_poll = True

        if should_poll:
            measurements = {}
            for key, meta in registers.items():
                if meta.get("c8y_ignore", "false").lower() == "true":
                    continue
                if "tag" not in meta:
                    continue
                read_result = plc.read(meta["tag"])
                if read_result is None:
                    continue
                value = read_result.value
                if isinstance(value, bool):
                    value = int(value)
                if "round" in meta:
                    try:
                        value = round(value, int(meta["round"]))
                    except Exception as e:
                        print(f"Warning: failed to round '{key}': {e}")
                entry = {"value": value}
                if "unit" in meta:
                    entry["unit"] = meta["unit"]
                measurements[key] = entry

            # Prevent sending if Batch_Reaction_Time is zero
            if BATCH_REACTION_TIME in measurements:
                brt_value = measurements[BATCH_REACTION_TIME]["value"]
                if brt_value == 0:
                    print("Skipping batch publish: Batch_Reaction_Time is 0.")
                    return {
                        "batch_end": batch_end_current,
                        "batch_number": batch_number_current
                    }

            if measurements:
                payload = build_payload(fragment, measurements, timestamp)
                publish_measurements(payload)

        return {
            "batch_end": batch_end_current,
            "batch_number": batch_number_current
        }

def main():
    config = load_config(CONFIG_FILE)
    prev_state = {
        "batch_end": False,
        "batch_number": None
    }

    while True:
        prev_state = read_plc_and_post_if_triggered(config, prev_state)
        time.sleep(1)

if __name__ == '__main__':
    main()

EOF

chmod +x "$GPAM_BATCH_SCRIPT"

echo "=== Creating Systemd Service for GPAM Live Measurements ==="
# --- Create systemd service file ---
cat > "$GPAM_LIVE_SERVICE_FILE" << EOF
[Unit]
Description=C8Y Measurement GPAM Live Data Service
After=network.target

[Service]
ExecStart=${VENV_DIR}/bin/python ${GPAM_LIVE_SCRIPT}
WorkingDirectory=/home/pi
StandardOutput=append:/var/log/c8y-gpam-live.log
StandardError=append:/var/log/c8y-gpam-live.log
Restart=always
User=pi
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
EOF

# --- Reload systemd and enable service ---
sudo systemctl daemon-reexec
sudo systemctl daemon-reload
sudo systemctl enable c8y-gpam-live.service
sudo systemctl restart c8y-gpam-live.service

echo "Systemd service installed and started: c8y-gpam-live.service"

echo "=== Creating Systemd Service for GPAM Batch Measurements ==="
# --- Create systemd service file ---
cat > "$GPAM_BATCH_SERVICE_FILE" << EOF
[Unit]
Description=C8Y Measurement GPAM Batch Data Service
After=network.target

[Service]
ExecStart=${VENV_DIR}/bin/python ${GPAM_BATCH_SCRIPT}
WorkingDirectory=/home/pi
StandardOutput=append:/var/log/c8y-gpam-batch.log
StandardError=append:/var/log/c8y-gpam-batch.log
Restart=always
User=pi
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
EOF

# --- Reload systemd and enable service ---
sudo systemctl daemon-reexec
sudo systemctl daemon-reload
sudo systemctl enable c8y-gpam-batch.service
sudo systemctl restart c8y-gpam-batch.service

echo "Systemd service installed and started: c8y-gpam-batch.service"

echo "=== Installing Python Configuration JSON for GPAM Alarm Data ==="
# --- Write Python script ---
cat > "$GPAM_ALARM_CONFIG_JSON" << 'EOF'
{
  "notes": "Matching Longview HMI 5/5/2025",
  "plc_ip": "192.168.1.52",
  "alarm_prefix": "gpam_alarm",
  "registers": {
    "fault_00": {
      "tag": "N13:0/0",
      "alarm_text": "Emergency Stop"
    },
    "fault_01": {
      "tag": "N13:0/1",
      "alarm_text": "Low Recirc Pressure"
    },
    "fault_02": {
      "tag": "N13:0/2",
      "alarm_text": "Water System Timeout"
    },
    "fault_03": {
      "tag": "N13:0/3",
      "alarm_text": "Excessive Caustic On Time"
    },
    "fault_04": {
      "tag": "N13:0/4",
      "alarm_text": "Excessive Acid On Time"
    },
    "fault_05": {
      "tag": "N13:0/5",
      "alarm_text": "Excessive Reaction Time"
    },
    "fault_06": {
      "tag": "N13:0/6",
      "alarm_text": "Water Out of Spec"
    },
    "fault_07": {
      "tag": "N13:0/7",
      "alarm_text": "CPAM Out of Spec"
    },
    "fault_08": {
      "tag": "N13:0/8",
      "alarm_text": "Turbidity Out of Spec"
    },
    "fault_09": {
      "tag": "N13:0/9",
      "alarm_text": "Glyoxal Out of Spec"
    },
    "fault_10": {
      "tag": "N13:0/10",
      "alarm_text": "Batch Size Out of Spec"
    },
    "fault_11": {
      "tag": "N13:0/11",
      "alarm_text": "Tank Not Empty On Startup"
    },
    "fault_12": {
      "tag": "N13:0/12",
      "alarm_text": "High High Reaction Mass"
    },
    "fault_13": {
      "tag": "N13:0/13",
      "alarm_text": "Low Low Turbidity Flow"
    },
    "fault_14": {
      "tag": "N13:0/14",
      "alarm_text": "Spare Fault Bit 1"
    },
    "fault_15": {
      "tag": "N13:0/15",
      "alarm_text": "Spare Fault Bit 2"
    },
    "alarm_16": {
      "tag": "N13:10/0",
      "alarm_text": "Low Turbidity Flow"
    },
    "alarm_17": {
      "tag": "N13:10/1",
      "alarm_text": "High High Storage Tank Float Reached"
    },
    "alarm_18": {
      "tag": "N13:10/2",
      "alarm_text": "Ingredient Addition Timeout"
    },
    "alarm_19": {
      "tag": "N13:10/3",
      "alarm_text": "Slow pH Response"
    },
    "alarm_20": {
      "tag": "N13:10/4",
      "alarm_text": "pH 1 High Buffer Differential"
    },
    "alarm_21": {
      "tag": "N13:10/5",
      "alarm_text": "pH 2 High Buffer Differential"
    },
    "alarm_22": {
      "tag": "N13:10/6",
      "alarm_text": "Low Bulk Tank Alarm"
    },
    "alarm_23": {
      "tag": "N13:10/7",
      "alarm_text": "Server Comms Failure"
    },
    "alarm_24": {
      "tag": "N13:10/8",
      "alarm_text": "Low Water Pressure"
    },
    "alarm_25": {
      "tag": "N13:10/9",
      "alarm_text": "Water Temp Out of Spec"
    },
    "alarm_26": {
      "tag": "N13:10/10",
      "alarm_text": "Spare Alarm Bit 1"
    },
    "alarm_27": {
      "tag": "N13:10/11",
      "alarm_text": "Spare Alarm Bit 2"
    },
    "alarm_28": {
      "tag": "N13:10/12",
      "alarm_text": "Spare Alarm Bit 3"
    },
    "alarm_29": {
      "tag": "N13:10/13",
      "alarm_text": "Spare Alarm Bit 4"
    },
    "alarm_30": {
      "tag": "N13:10/14",
      "alarm_text": "Spare Alarm Bit 5"
    },
    "alarm_31": {
      "tag": "N13:10/15",
      "alarm_text": "Spare Alarm Bit 6"
    },
    "alarm_32": {
      "type": "ping",
      "alarm_text": "Cloud to PLC Comms Down"
    }
  }
}

EOF

sudo chown tedge:tedge "$GPAM_ALARM_CONFIG_JSON"

chmod +x "$GPAM_ALARM_CONFIG_JSON"

# --- Add Log Access to tedge ---
sudo tee -a "$TEDGE_CONFIG_PLUGIN" >/dev/null <<EOF
[[files]]
path = "${GPAM_ALARM_CONFIG_JSON}"
type = "config_gpam_alarm.json"

EOF

echo "=== Installing GPAM Alarm Data Python Script ==="
# --- Write Python script ---
cat > "$GPAM_ALARM_SCRIPT" << EOF
import json
import time
import subprocess
import platform
from pycomm3 import SLCDriver

CONFIG_FILE = '$GPAM_ALARM_CONFIG_JSON'

def load_config(path):
    with open(path, 'r') as f:
        return json.load(f)

def publish_alarm(alarm_type, alarm_text, status, prefix):
    payload = {
        "type": alarm_type,
        "text": alarm_text,
        "status": status,
        "severity": "critical",
        "source": { "id": prefix }
    }
    cmd = ["tedge", "mqtt", "pub", "te/alarms", json.dumps(payload)]
    subprocess.run(cmd, check=False)

def is_host_reachable(ip):
    count_flag = "-n" if platform.system().lower() == "windows" else "-c"
    try:
        result = subprocess.run(["ping", count_flag, "1", ip], stdout=subprocess.DEVNULL)
        return result.returncode == 0
    except Exception as e:
        print(f"[ERROR] Ping failed: {e}")
        return False

# Track alarm states
active_alarms = {}

while True:
    config = load_config(CONFIG_FILE)
    plc_ip = config["plc_ip"]
    alarm_prefix = config.get("alarm_prefix", "PLC_Alarm")
    registers = config["registers"]

    plc_available = is_host_reachable(plc_ip)

    # Handle ping alarm
    for name, reg in registers.items():
        if reg.get("type") == "ping":
            alarm_type = f"{alarm_prefix}_{name}"
            alarm_text = reg.get("alarm_text", name)
            if not plc_available and not active_alarms.get(name):
                publish_alarm(alarm_type, alarm_text, "ACTIVE", alarm_prefix)
                active_alarms[name] = True
            elif plc_available and active_alarms.get(name):
                publish_alarm(alarm_type, alarm_text, "CLEARED", alarm_prefix)
                active_alarms.pop(name)

    # Skip tag reads if PLC unreachable
    if not plc_available:
        time.sleep(2)
        continue

    # Poll tags via SLCDriver
    try:
        with SLCDriver(plc_ip) as plc:
            for name, reg in registers.items():
                if reg.get("type") == "ping":
                    continue  # Skip ping alarms here

                tag = reg["tag"]
                alarm_type = f"{alarm_prefix}_{name}"
                alarm_text = reg.get("alarm_text", name)

                result = plc.read(tag)
                if not result or result.error:
                    print(f"[ERROR] Failed to read {tag}: {result.error}")
                    continue

                value = bool(result.value)

                if value and not active_alarms.get(name):
                    publish_alarm(alarm_type, alarm_text, "ACTIVE", alarm_prefix)
                    active_alarms[name] = True
                elif not value and active_alarms.get(name):
                    publish_alarm(alarm_type, alarm_text, "CLEARED", alarm_prefix)
                    active_alarms.pop(name)

    except Exception as e:
        print(f"[ERROR] PLC communication error: {e}")

    time.sleep(2)

EOF

chmod +x "$GPAM_ALARM_SCRIPT"

echo "=== Creating Systemd Service for GPAM Alarm Service ==="
# --- Create systemd service file ---
cat > "$GPAM_ALARM_SERVICE_FILE" << EOF
[Unit]
Description=C8Y Alarm GPAM Service
After=network.target

[Service]
ExecStart=${VENV_DIR}/bin/python ${GPAM_ALARM_SCRIPT}
WorkingDirectory=/home/pi
StandardOutput=append:/var/log/c8y-gpam-alarm.log
StandardError=append:/var/log/c8y-gpam-alarm.log
Restart=always
User=pi
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
EOF

# --- Reload systemd and enable service ---
sudo systemctl daemon-reexec
sudo systemctl daemon-reload
sudo systemctl enable c8y-gpam-alarm.service
sudo systemctl restart c8y-gpam-alarm.service

echo "Systemd service installed and started: c8y-gpam-alarm.service"

echo "=== Creating Systemd Service for GPAM Alarms ==="
# --- Create systemd service file ---
cat > "$GPAM_ALARM_SERVICE_FILE" << EOF
[Unit]
Description=C8Y Alarm GPAM Alarm Data Service
After=network.target

[Service]
ExecStart=${VENV_DIR}/bin/python ${GPAM_ALARM_SCRIPT}
WorkingDirectory=/home/pi
StandardOutput=append:/var/log/c8y-gpam-alarm.log
StandardError=append:/var/log/c8y-gpam-alarm.log
Restart=always
User=pi
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
EOF

# --- Reload systemd and enable service ---
sudo systemctl daemon-reexec
sudo systemctl daemon-reload
sudo systemctl enable c8y-gpam-alarm.service
sudo systemctl restart c8y-gpam-alarm.service

echo "Systemd service installed and started: c8y-gpam-alarm.service"

# Load "GPAM" Supported Measurements
echo "Load c8y_SupportedMeasurements: GPAM"
sudo tedge mqtt pub "te/device/main///twin/c8y_SupportedMeasurements" "[\"GPAM\"]"
