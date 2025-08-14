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

