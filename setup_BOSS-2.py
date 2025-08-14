{
  "notes": "Batch measurement config for BOSS system",
  "plc_ip": "192.168.1.156",
  "fragment": "BOSS",
  "registers": {
    "Batch_End": {
      "tag": "batchComplete",
      "c8y_ignore": "true"
    },
    "TARGET_VOLUME": {
      "tag": "TARGET_VOLUME",
      "unit": "GAL",
      "round": 3
    },
    "TOTAL_DISPENSED": {
      "tag": "VOLUME_totalDispensed",
      "unit": "GAL",
      "round": 3
    },
    "VOLUME_dispensed_1": {
      "tag": "VOLUME_dispensed_1",
      "unit": "GAL",
      "round": 3
    },
    "VOLUME_dispensed_2": {
      "tag": "VOLUME_dispensed_2",
      "unit": "GAL",
      "round": 3
    },
    "VOLUME_dispensed_3": {
      "tag": "VOLUME_dispensed_3",
      "unit": "GAL",
      "round": 3
    },
    "VOLUME_dispensed_4": {
      "tag": "VOLUME_dispensed_4",
      "unit": "GAL",
      "round": 3
    },
    "VOLUME_dispensed_5": {
      "tag": "VOLUME_dispensed_5",
      "unit": "GAL",
      "round": 3
    },
    "VOLUME_dispensed_6": {
      "tag": "VOLUME_dispensed_6",
      "unit": "GAL",
      "round": 3
    },
    "VOLUME_dispensed_7": {
      "tag": "VOLUME_dispensed_7",
      "unit": "GAL",
      "round": 3
    },
    "VOLUME_dispensed_8": {
      "tag": "VOLUME_dispensed_8",
      "unit": "GAL",
      "round": 3
    },
    "VOLUME_dispensed_9": {
      "tag": "VOLUME_dispensed_9",
      "unit": "GAL",
      "round": 3
    },
    "username": {
      "stringValue": {
        "tag": "ACTIVE_USERNAME"
      },
      "value": {
        "tag": "ACTIVE_USER"
      }
    },
    "recipeName": {
      "stringValue": {
        "tag": "CURRENT_RECIPE"
      },
      "value": {
        "tag": "RECIPE_SELECTOR"
      }
    },
    "location": {
      "stringValue": {
        "tag": "CURRENT_LOCATION"
      },
      "value": {
        "tag": "RECIPE_SELECTOR"
      }
    },
    "aborted": {
      "tag": "FLAG_aborted"
    }
  }
}

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


