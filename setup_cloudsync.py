echo "=== Installing CloudSync Data Python Script ==="
# --- Write Python script ---
cat > "$CloudSync_SCRIPT" << EOF
import subprocess
import base64
import json
import time
import math
import requests
import argparse
import socket
import urllib3
from datetime import datetime, timezone, timedelta
from typing import Union
from pymodbus.client import ModbusTcpClient
from pymodbus.exceptions import ModbusException

parser = argparse.ArgumentParser()
parser.add_argument('--print', dest='verbose', action='store_true', help='Enable print statements')
args = parser.parse_args()
verbose = args.verbose

def timestamp():
    return datetime.utcnow().strftime("[%Y-%m-%dT%H:%M:%SZ]")

def vprint(*args, **kwargs):
    if verbose:
        print(timestamp(), *args, **kwargs)

with open("$CloudSync_CONFIG_JSON", "r") as f:
    config = json.load(f)

MOXA_AO = config["MOXA_AO"]
MOXA_DIO = config["MOXA_DIO"]
cloud_cfg = config["cloud"]

STALE_TIMEOUT = cloud_cfg.get("stale_timeout", 900)
CLOUD_FAIL_TIMEOUT = cloud_cfg.get("cloud_fail_timeout", 300)

active_alarms = {}
last_di_states = {}
last_do_states = {}

def get_device_jwt():
    try:
        result = subprocess.run(
            ["mosquitto_rr", "-t", "c8y/s/uat", "-e", "c8y/s/dat", "-m", ""],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=5
        )
        jwt_raw = result.stdout.decode().strip()
        if jwt_raw.startswith("71,"):
            return jwt_raw[3:]
        else:
            raise RuntimeError(f"Unexpected JWT format: {jwt_raw}")
    except Exception as e:
        print(timestamp(), f"Failed to get JWT: {e}")
        exit(1)

def decode_jwt_payload(jwt):
    payload_b64 = jwt.split(".")[1]
    payload_b64 += "=" * (-len(payload_b64) % 4)
    payload_json = base64.urlsafe_b64decode(payload_b64.encode()).decode()
    return json.loads(payload_json)

def get_device_internal_id(jwt_token, base_url, external_id):
    url = f"{base_url}/identity/externalIds/c8y_Serial/{external_id}"
    headers = {
        "Authorization": f"Bearer {jwt_token}",
        "Accept": "application/json"
    }
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()["managedObject"]["id"]
    else:
        print(timestamp(), f"Error getting internal ID: {response.status_code}, {response.text}")
        exit(1)

def get_latest_measurements(jwt_token, base_url, device_id, series: str, retries: int = 3, delay: float = 5.0):
    future_time = (datetime.utcnow() + timedelta(minutes=30)).isoformat() + "Z"
    url = f"{base_url}/measurement/measurements?source={device_id}&pageSize=1&revert=true&dateTo={future_time}&valueFragmentSeries={series}"
    headers = {
        "Authorization": f"Bearer {jwt_token}",
        "Accept": "application/json"
    }

    for attempt in range(retries):
        try:
            response = requests.get(url, headers=headers, timeout=10)
            if response.status_code == 200:
                return response.json()
            else:
                raise RuntimeError(f"Error fetching measurements: {response.status_code}, {response.text}")
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout, urllib3.exceptions.HTTPError, socket.gaierror) as e:
            vprint(f"Attempt {attempt + 1} failed: {e}")
            time.sleep(delay)
        except Exception as e:
            raise
    raise RuntimeError(f"Failed to fetch measurements after {retries} attempts.")

def modbus_scaling(input_val: float, low: float, high: float, resolution: int) -> int:
    modbus_out_float = (input_val - low) / (high - low) * float(resolution)
    return int(math.ceil(modbus_out_float))

def write_and_verify_register(ip_address: str, register_address: int, value: int) -> bool:
    try:
        client = ModbusTcpClient(ip_address)
        client.connect()
        write_response = client.write_register(register_address - 1, value)
        time.sleep(0.1)
        read_response = client.read_holding_registers(register_address - 1, 1)
        client.close()

        if write_response.isError() or not read_response or read_response.registers[0] != value:
            return False
        return True
    except Exception as e:
        vprint(f"Modbus exception: {e}")
        return False

def toggle_coil(ip: str, index: int, state: bool, label: str = ""):
    global last_do_states
    if last_do_states.get(index) == state:
        return
    try:
        client = ModbusTcpClient(ip)
        client.connect()
        client.write_coil(index, state)
        client.close()
        last_do_states[index] = state
        vprint(f"Toggled DO{index} ({label}) to {int(state)}")
    except Exception as e:
        vprint(f"Failed to toggle coil DO{index}: {e}")

def read_discrete_inputs(ip: str, inputs: dict):
    global last_di_states
    try:
        client = ModbusTcpClient(ip)
        client.connect()
        indices = [inputs[k]["index"] for k in inputs]
        min_index = min(indices)
        count = max(indices) - min_index + 1
        response = client.read_discrete_inputs(min_index, count)
        client.close()
        if not response.isError():
            for key, val in inputs.items():
                index = val["index"]
                state = response.bits[index - min_index]
                if last_di_states.get(index) != state:
                    last_di_states[index] = state
                    label = val.get("label", "")
                    vprint(f"DI{index} ({label}): {state}")

                    # DI0 → DO2
                    if index == 0:
                        do2 = MOXA_DIO["coils"]["DO2"]
                        toggle_coil(ip, do2["index"], state, do2["label"])
                    # DI1 → DO3
                    elif index == 1:
                        do3 = MOXA_DIO["coils"]["DO3"]
                        toggle_coil(ip, do3["index"], state, do3["label"])
    except Exception as e:
        vprint(f"Failed to read DIs: {e}")

def publish_alarm(ip: str, key: str, active: bool, message: str):
    global active_alarms
    alarm_id = f"{key}_{ip.replace('.', '_')}"
    topic = f"te/device/main///a/{alarm_id}"

    if active and not active_alarms.get(alarm_id):
        active_alarms[alarm_id] = True
        payload = json.dumps({
            "text": message,
            "severity": "major"
        })
        subprocess.run(["tedge", "mqtt", "pub", topic, payload])
        vprint(f"Alarm raised: {message}")
    elif not active and active_alarms.get(alarm_id):
        active_alarms.pop(alarm_id, None)
        subprocess.run(["tedge", "mqtt", "pub", "-r", "-q", "2", topic, ""])
        vprint(f"Alarm cleared: {message}")

if __name__ == "__main__":
    jwt_token = get_device_jwt()
    payload = decode_jwt_payload(jwt_token)
    expiration = int(payload.get("exp"))
    external_id = payload.get("sub").replace("device_", "")
    base_url = f"https://{payload.get('aud')}"
    device_id = get_device_internal_id(jwt_token, base_url, external_id)

    last_poll_time = time.time()
    dio_ip = MOXA_DIO["ip"]
    dio_cfg = MOXA_DIO

    while True:
        current_time = time.time()
        if current_time > (expiration - 60):
            jwt_token = get_device_jwt()
            payload = decode_jwt_payload(jwt_token)
            expiration = int(payload.get("exp"))

        try:
            m = get_latest_measurements(jwt_token, base_url, device_id, cloud_cfg["series"])
            last_poll_time = current_time
            meas = m["measurements"][0]
            value = float(meas[cloud_cfg["fragment"]][cloud_cfg["series"]]["value"])
            timestamp_str = meas["time"]
            ts_dt = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
            age_sec = (datetime.now(timezone.utc) - ts_dt).total_seconds()

            ao_cfg = MOXA_AO["registers"]["AO0"]
            scaled = modbus_scaling(value, ao_cfg["min"], ao_cfg["max"], ao_cfg["resolution"])
            success = write_and_verify_register(MOXA_AO["ip"], ao_cfg["register"], scaled)

            publish_alarm(MOXA_AO["ip"], "modbus_write", not success,
                          f"Modbus write/readback failed for {ao_cfg['label']}")
            stale = age_sec > STALE_TIMEOUT
            publish_alarm("cloud", "cloud_stale", stale,
                          f"{cloud_cfg['series']} stale: {value} {ao_cfg['units']} @ {timestamp_str}")
        except Exception as e:
            vprint(f"Error during loop: {e}")
            if current_time - last_poll_time > CLOUD_FAIL_TIMEOUT:
                publish_alarm("cloud", "cloud_polling", True,
                              f"Cloud polling failed for > {CLOUD_FAIL_TIMEOUT}s")
            else:
                publish_alarm("cloud", "cloud_polling", False, "")

        # DO4: Beacon Blue (on = polling/stale ok)
        beacon_ok = (
            "cloud_stale_cloud" not in active_alarms and
            "cloud_polling_cloud" not in active_alarms
        )
        toggle_coil(dio_ip, dio_cfg["coils"]["DO4"]["index"], beacon_ok, dio_cfg["coils"]["DO4"]["label"])

        # DO0: LCL toggle on any alarm
        toggle_coil(dio_ip, dio_cfg["coils"]["DO0"]["index"], bool(active_alarms), dio_cfg["coils"]["DO0"]["label"])

        # DO1: Beacon RED on any alarm
        toggle_coil(dio_ip, dio_cfg["coils"]["DO1"]["index"], bool(active_alarms), dio_cfg["coils"]["DO1"]["label"])

        # Read digital inputs
        read_discrete_inputs(dio_ip, dio_cfg["discrete_inputs"])

        time.sleep(10)

EOF

echo "=== Installing CloudSync Measurement Data Python Script ==="
# --- Write Python script ---
cat > "$CloudSync_MEASUREMENT_SCRIPT" << EOF
import json
import time
import datetime
import argparse
import subprocess
from pymodbus.client import ModbusTcpClient

# Argument parsing
parser = argparse.ArgumentParser()
parser.add_argument("--print", action="store_true", help="Enable debug output")
args = parser.parse_args()

# Load configuration
with open("$CloudSync_CONFIG_JSON") as f:
    config = json.load(f)

cloud_cfg = config["cloud"]
fragment = cloud_cfg["fragment"]
topic = 'te/device/main///m/OPTIX'

# Error tracking
last_errors = {
    "MOXA_AO": False,
    "MOXA_AI": False,
    "MOXA_DI": False
}

def scale_modbus_to_physical(raw_val, min_val, max_val, resolution):
    scaled = ((raw_val / resolution) * (max_val - min_val)) + min_val
    return round(scaled, 2)

def read_modbus_register(ip, register, kind="holding"):
    try:
        client = ModbusTcpClient(ip, timeout=2)
        client.connect()
        if kind == "holding":
            result = client.read_holding_registers(address=register, count=1)
        else:
            result = client.read_input_registers(address=register, count=1)
        client.close()
        if result.isError():
            return None
        return result.registers[0]
    except Exception as e:
        if args.print:
            print(f"Modbus read error from {ip}: {e}")
        return None

def read_modbus_discrete_input(ip, index):
    try:
        client = ModbusTcpClient(ip, timeout=2)
        client.connect()
        result = client.read_discrete_inputs(address=index, count=1)
        client.close()
        if result.isError():
            return None
        return int(result.bits[0])
    except Exception as e:
        if args.print:
            print(f"Discrete input read error from {ip}: {e}")
        return None

def read_modbus_coil(ip, index):
    try:
        client = ModbusTcpClient(ip, timeout=2)
        client.connect()
        result = client.read_coils(address=index, count=1)
        client.close()
        if result.isError():
            return None
        return int(result.bits[0])
    except Exception as e:
        if args.print:
            print(f"Coil read error from {ip}: {e}")
        return None

def publish_combined_measurement(data_dict):
    payload = {fragment: data_dict}
    try:
        json_payload = json.dumps(payload)
        if args.print:
            print(f"Publishing: {json_payload}")
        subprocess.run(["tedge", "mqtt", "pub", topic, json_payload], check=True)
    except subprocess.CalledProcessError as e:
        if args.print:
            print(f"Publish error: {e}")

def publish_alarm(alarm_type, text, severity="MAJOR", status="ACTIVE"):
    topic = f"te/device/main///a/{alarm_type}"
    payload = {
        "text": text,
        "severity": severity,
        "status": status
    }
    try:
        json_payload = json.dumps(payload)
        if args.print:
            print(f"Publishing alarm to {topic}: {json_payload}")
        subprocess.run(["tedge", "mqtt", "pub", topic, json_payload], check=True)
    except subprocess.CalledProcessError as e:
        if args.print:
            print(f"Alarm publish error: {e}")

def sleep_until_next_minute():
    now = datetime.datetime.now()
    next_minute = (now + datetime.timedelta(minutes=1)).replace(second=0, microsecond=0)
    time.sleep((next_minute - now).total_seconds())

if __name__ == "__main__":
    while True:
        sleep_until_next_minute()
        measurement = {}

        # Read AO
        ao_cfg = config.get("MOXA_AO", {})
        for key, chan in ao_cfg.get("registers", {}).items():
            val = read_modbus_register(ao_cfg["ip"], chan["register"] - 1, "holding")
            if val is not None:
                scaled = scale_modbus_to_physical(val, chan["min"], chan["max"], chan["resolution"])
                measurement[chan["series"]] = scaled
                if last_errors["MOXA_AO"]:
                    publish_alarm("MOXA_AO_ERROR", "MOXA AO Modbus error resolved", status="CLEARED")
                    last_errors["MOXA_AO"] = False
            else:
                if not last_errors["MOXA_AO"]:
                    publish_alarm("MOXA_AO_ERROR", f"Failed to read {chan['label']}")
                    last_errors["MOXA_AO"] = True

        # Read AI
        ai_cfg = config.get("MOXA_AI", {})
        for key, chan in ai_cfg.get("registers", {}).items():
            val = read_modbus_register(ai_cfg["ip"], chan["register"], "input")
            if val is not None:
                scaled = scale_modbus_to_physical(val, chan["min"], chan["max"], chan["resolution"])
                measurement[chan["series"]] = scaled
                if last_errors["MOXA_AI"]:
                    publish_alarm("MOXA_AI_ERROR", "MOXA AI Modbus error resolved", status="CLEARED")
                    last_errors["MOXA_AI"] = False
            else:
                if not last_errors["MOXA_AI"]:
                    publish_alarm("MOXA_AI_ERROR", f"Failed to read {chan['label']}")
                    last_errors["MOXA_AI"] = True

        # Read DIO inputs
        dio_cfg = config.get("MOXA_DIO", {})
        dio_error = False

        for key, chan in dio_cfg.get("discrete_inputs", {}).items():
            if "series" not in chan:
                continue
            val = read_modbus_discrete_input(dio_cfg["ip"], chan["index"])
            if val is not None:
                measurement[chan["series"]] = val
            else:
                dio_error = True
                if args.print:
                    print(f"Failed to read DI {key}: {chan.get('label', '')}")

        if dio_error:
            if not last_errors["MOXA_DI"]:
                publish_alarm("MOXA_DI_ERROR", "Failed to read from MOXA DI")
                last_errors["MOXA_DI"] = True
        else:
            if last_errors["MOXA_DI"]:
                publish_alarm("MOXA_DI_ERROR", "MOXA DI Modbus error resolved", status="CLEARED")
                last_errors["MOXA_DI"] = False

        if measurement:
            publish_combined_measurement(measurement)
        elif args.print:
            print("No valid data to publish this cycle.")

EOF

echo "Systemd service installed and started: c8y-cloudsync-measurement.service"

echo "=== Installing CloudSync Stepper Data Python Script ==="
# --- Write Python script ---
cat > "$CloudSync_STEPPER_SCRIPT" << EOF
import time
import subprocess

# Configuration
min_val = 1
max_val = 20
step = 0.5
interval_seconds = 300

def publish_measurement(value):
    topic = "te/device/main///m/OPTIX"
    payload = f'{{"OPTIX": {{"Cloud_Value": {value}}}}}'
    
    try:
        subprocess.run(["tedge", "mqtt", "pub", topic, payload], check=True)
        print(f"Published Cloud_Value = {value}")
    except subprocess.CalledProcessError as e:
        print(f"Failed to publish measurement: {e}")

if __name__ == "__main__":
    value = min_val
    direction = step

    while True:
        publish_measurement(value)
        value += direction

        if value >= max_val or value <= min_val:
            direction *= -1  # Reverse direction at bounds

        time.sleep(interval_seconds)

EOF

