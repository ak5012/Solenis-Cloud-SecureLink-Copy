
echo "=== Installing BOSS Batch Data Python Script ======"
# --- Write Python script ---
cat > "$BOSS_BATCH_SCRIPT" << EOF
from pycomm3 import LogixDriver
import json
from datetime import datetime, timezone
import time
import subprocess

CONFIG_FILE = '/etc/tedge/plugins/boss/config_boss_batch.json'

def load_config(filename):
    with open(filename) as f:
        return json.load(f)

def read_tag(plc, tag):
    try:
        return plc.read(tag).value
    except Exception as e:
        print(f"Error reading tag {tag}: {e}")
        return None

def round_value(val, digits):
    if val is None:
        return None
    if isinstance(val, (float, int)) and digits is not None:
        return round(val, digits)
    return val

def get_time():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')

def publish(payload_json):
    topic = "c8y/measurement/measurements/create"
    cmd = ['tedge', 'mqtt', 'pub', topic, payload_json]
    subprocess.run(cmd)

def process_register_entry(plc, key, props):
    if isinstance(props, dict):
        if 'tag' in props:
            val = read_tag(plc, props['tag'])
            # Convert BOOL to 1 or 0
            if isinstance(val, bool):
                val = 1 if val else 0
            rnd = props.get('round')
            if rnd is not None:
                try:
                    rnd = int(rnd)
                except ValueError:
                    rnd = None
            val_rounded = round_value(val, rnd)
            result = {'value': val_rounded}
            unit = props.get('unit')
            if unit:
                result['unit'] = unit
            return result
        else:
            # Nested structure: stringValue, value, etc.
            result = {}
            for subkey, subprops in props.items():
                if isinstance(subprops, dict) and 'tag' in subprops:
                    val = read_tag(plc, subprops['tag'])
                    result[subkey] = val
            return result
    else:
        return None

def main():
    config = load_config(CONFIG_FILE)
    plc_ip = config.get('plc_ip')
    registers = config.get('registers', {})
    fragment = config.get('fragment', 'BOSS')

    batch_end_tag = registers.get('Batch_End', {}).get('tag', 'Batch_End')
    last_batch_end = 0

    with LogixDriver(plc_ip) as plc:
        while True:
            batch_end = read_tag(plc, batch_end_tag)
            if batch_end is None:
                time.sleep(1)
                continue

            if batch_end and not last_batch_end:
                fragment_data = {}

                for key, props in registers.items():
                    if isinstance(props, dict) and props.get('c8y_ignore', 'false').lower() == 'true':
                        continue
                    if key == 'Batch_End':
                        continue

                    entry = process_register_entry(plc, key, props)
                    if entry is not None:
                        fragment_data[key] = entry

                payload = {
                    "time": get_time(),
                    "type": fragment,
                    fragment: fragment_data
                }

                payload_json = json.dumps(payload)

                print(f"Publishing payload:\n{payload_json}\n")

                publish(payload_json)

            last_batch_end = batch_end
            time.sleep(1)

if __name__ == "__main__":
    main()

EOF

echo "=== Installing BOSS Alarm Data Python Script ==="
# --- Write Python script ---
cat > "$BOSS_ALARM_SCRIPT" << EOF
import json
import time
import subprocess
import platform
from pycomm3 import LogixDriver  # Updated import

CONFIG_FILE = '$BOSS_ALARM_CONFIG_JSON'

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

    # Handle ping alarms
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

    # Poll tags using LogixDriver
    try:
        with LogixDriver(plc_ip) as plc:
            if not plc.connected:
                print(f"[ERROR] Could not connect to PLC at {plc_ip}")
                time.sleep(2)
                continue

            for name, reg in registers.items():
                if reg.get("type") == "ping":
                    continue  # Skip ping alarms here

                tag = reg["tag"]
                alarm_type = f"{alarm_prefix}_{name}"
                alarm_text = reg.get("alarm_text", name)

                result = plc.read(tag)
                if not result or result.error:
                    print(f"[ERROR] Failed to read {tag}: {result.error if result else 'None'}")
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

echo "=== Installing BOSS User Sync Egress Python Script ==="
# --- Write Python script ---
cat > "$BOSS_USER_EGRESS_SCRIPT" << EOF
from pycomm3 import LogixDriver
import subprocess
import json
from datetime import datetime, timezone
import time

PLC_IP = '192.168.1.156'
USER_START = 1
USER_END = 100

def get_tedge_twin_name(timeout=5):
    try:
        result = subprocess.run(
            [
                "mosquitto_sub",
                "-t", "te/device/main///twin/name",
                "-C", "1",
                "-V", "mqttv311",
                "-q", "1"
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            text=True
        )
        if result.returncode == 0:
            return result.stdout.strip().strip('"')
        else:
            raise RuntimeError(f"Command failed: {result.stderr.strip()}")
    except subprocess.TimeoutExpired:
        raise TimeoutError("Timed out waiting for retained twin name.")
    except FileNotFoundError:
        raise RuntimeError("mosquitto_sub not found. Please install Mosquitto clients.")
    except Exception as e:
        raise RuntimeError(f"Unexpected error: {e}")

def read_string_tag(plc, tag_name):
    result = plc.read(tag_name)
    if result and result.value:
        return str(result.value).strip()
    return None

def read_lint_tag(plc, tag_name):
    result = plc.read(tag_name)
    if result and result.value is not None:
        return int(result.value)
    return None

def decode_lint_to_bools(lint_val):
    return [(lint_val >> i) & 1 == 1 for i in range(64)]

def read_bool_tag(plc, tag_name):
    result = plc.read(tag_name)
    if result is not None:
        return bool(result.value)
    return None

def read_bool_array_tag(plc, base_tag, size):
    values = {}
    for i in range(size + 1):
        tag = f"{base_tag}[{i}]"
        value = read_bool_tag(plc, tag)
        values[i] = value
    return values

def read_usint_array(plc, tag_name, start, end):
    values = {}
    for i in range(start, end + 1):
        tag = f"{tag_name}[{i}]"
        result = plc.read(tag)
        values[i] = int(result.value) if result and result.value is not None else 0
    return values

def read_local_users(plc):
    users = []
    admin_flags = read_bool_array_tag(plc, 'FLAG_userAdmin', USER_END)
    replay_flags = read_bool_array_tag(plc, 'FLAG_userReplay', USER_END)
    flat_rfid = read_usint_array(plc, 'VAR_userRFID_FLAT', 0, 403)

    for i in range(USER_START, USER_END + 1):
        user = {}
        username = read_string_tag(plc, f'STRING_username[{i}]')
        if username:
            user['username'] = username
            lint_val = read_lint_tag(plc, f'FLAG_userPermissions[{i}]')
            if lint_val is not None:
                full_bits = decode_lint_to_bools(lint_val)
                user['permissions'] = [1 if b else 0 for b in full_bits[1:51]]  # bits 1�50 as 1/0
            else:
                user['permissions'] = []

            user['isAdmin'] = 1 if admin_flags.get(i, False) else 0
            user['canReplay'] = 1 if replay_flags.get(i, False) else 0

            base_index = i * 4
            user['rfid'] = [
                flat_rfid.get(base_index + 0, 0),
                flat_rfid.get(base_index + 1, 0),
                flat_rfid.get(base_index + 2, 0),
                flat_rfid.get(base_index + 3, 0)
            ]

            users.append(user)

    return {
        'localUsers': {
            'users': users,
            'lastUpdated': datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
        }
    }

def publish_to_device_twin(json_fragment, device_name):
    topic = f'c8y/inventory/managedObjects/update/{device_name}'
    payload_str = json.dumps(json_fragment)
    print(f"Publishing to topic: {topic}")
    try:
        subprocess.run(
            ['sudo', 'tedge', 'mqtt', 'pub', topic, payload_str],
            check=True
        )
        print("Publish complete.")
    except subprocess.CalledProcessError as e:
        print(f"MQTT publish failed: {e}")

if __name__ == "__main__":
    try:
        device_name = get_tedge_twin_name()
        print(f"Resolved device twin name: {device_name}")
    except Exception as e:
        print(f"Error retrieving device name: {e}")
        exit(1)

    last_hmi_submit = False
    last_remote_submit = False

    while True:
        try:
            with LogixDriver(PLC_IP) as plc:
                hmi_submit = read_bool_tag(plc, 'HMI_submitUsers')
                remote_submit = read_bool_tag(plc, 'FLAG_remoteSubmitSEND')

                print(f"HMI_submitUsers: {hmi_submit}")
                print(f"FLAG_remoteSubmitSEND: {remote_submit}")

                trigger = (
                    (hmi_submit and not last_hmi_submit) or
                    (remote_submit and not last_remote_submit)
                )

                if trigger:
                    print("Rising edge detected, reading users and publishing...")
                    user_data = read_local_users(plc)
                    print("Publishing the following JSON payload:")
                    print(json.dumps(user_data, indent=2))
                    publish_to_device_twin(user_data, device_name)

                last_hmi_submit = hmi_submit
                last_remote_submit = remote_submit

        except Exception as e:
            print(f"Error during PLC read or publish: {e}")

        time.sleep(1)

EOF

echo "=== Installing BOSS Recipe Sync Ingress Python Script ==="
# --- Write Python script ---
cat > "$BOSS_RECIPE_INGRESS_SCRIPT" << EOF
import json
import paho.mqtt.client as mqtt
from pycomm3 import LogixDriver
import subprocess
import time

# Configuration
MQTT_BROKER = "localhost"
MQTT_PORT = 1883
MQTT_TOPIC = "c8y/devicecontrol/notifications"

PLC_IP = "192.168.1.156"
FLAG_TAG = "FLAG_remoteSubmit"  # Changed here
NAME_ARRAY_TAG = "STRING_username"
PASSWORD_ARRAY_TAG = "STRING_userPassword"
PERMISSIONS_ARRAY_TAG = "FLAG_userPermissions"
MAX_RETRIES = 10

def on_connect(client, userdata, flags, rc):
    if rc == 0:
        print("Connected to MQTT broker.")
        client.subscribe(MQTT_TOPIC)
    else:
        print(f"Failed to connect, return code {rc}")

def try_write(plc, tag, value):
    for attempt in range(1, MAX_RETRIES + 1):
        result = plc.write(tag, value)
        if result and result.error is None:
            print(f"Wrote {value} to {tag} (attempt {attempt})")
            return True
        print(f"Attempt {attempt} failed writing {value} to {tag}")
        time.sleep(0.2)
    return False

def publish_exec_status(code: str, message: str):
    try:
        cmd = ["sudo", "tedge", "mqtt", "pub", "-r", "-q", "1", "c8y/s/us", f"{code},boss_updateUser,{message}"]
        subprocess.run(cmd, check=True)
        print(f"Published: {code},boss_updateUser,{message}")
    except subprocess.CalledProcessError as e:
        print(f"Failed to publish status message ({code}): {e}")

def on_message(client, userdata, msg):
    try:
        payload = json.loads(msg.payload.decode())
        user_update = payload.get("boss_updateUser")

        if user_update and "key" in user_update and "permissions" in user_update:
            key = user_update["key"]
            permissions = user_update["permissions"]
            username = user_update.get("username", "")
            password = user_update.get("password", "")

            if not isinstance(key, int) or key <= 0 or key > 100:
                print(f"Invalid key index: {key}")
                return

            if not (isinstance(permissions, list) and len(permissions) == 50 and all(bit in (0,1) for bit in permissions)):
                print("permissions must be a list of 50 zeros or ones.")
                return

            # Convert permissions list to LINT, skipping bit 0 in PLC
            lIntValue = 0
            for i, bit in enumerate(permissions):
                if bit == 1:
                    lIntValue |= (1 << (i + 1))  # Shift left by 1 to skip bit 0

            print(f"Writing username, password, permissions as LINT {lIntValue:#018x} using key = {key}")
            publish_exec_status("501", "User Change Executing")

            with LogixDriver(PLC_IP) as plc:
                # Write STRING_username[key]
                username_tag = f"{NAME_ARRAY_TAG}[{key}]"
                if not try_write(plc, username_tag, username):
                    print(f"Failed to write username '{username}' to {username_tag}")
                    publish_exec_status("502", "User Change Failed")
                    return

                # Write STRING_userPassword[key]
                password_tag = f"{PASSWORD_ARRAY_TAG}[{key}]"
                if not try_write(plc, password_tag, password):
                    print(f"Failed to write password to {password_tag}")
                    publish_exec_status("502", "User Change Failed")
                    return

                # Write FLAG_userPermissions[key] = LINT
                flag_perm_tag = f"{PERMISSIONS_ARRAY_TAG}[{key}]"
                if not try_write(plc, flag_perm_tag, lIntValue):
                    print(f"Failed to write LINT {lIntValue} to {flag_perm_tag}")
                    publish_exec_status("502", "User Change Failed")
                    return

                # Set trigger flag
                if try_write(plc, FLAG_TAG, True):
                    print(f"Set {FLAG_TAG} = TRUE")
                    publish_exec_status("503", "User Change Successful")
                else:
                    print(f"Failed to set {FLAG_TAG} after {MAX_RETRIES} attempts.")
                    publish_exec_status("502", "User Change Failed")
        else:
            print("Missing boss_updateUser, key, or permissions in payload.")
    except json.JSONDecodeError:
        print("Received non-JSON payload.")
    except Exception as e:
        print(f"Error handling message: {e}")
        publish_exec_status("502", "User Change Failed")

# MQTT client setup
client = mqtt.Client()
client.on_connect = on_connect
client.on_message = on_message

try:
    client.connect(MQTT_BROKER, MQTT_PORT, 60)
    client.loop_forever()
except KeyboardInterrupt:
    print("Disconnected from MQTT broker.")
except Exception as e:
    print(f"MQTT connection failed: {e}")

EOF



