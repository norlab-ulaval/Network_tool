#!/usr/bin/python3
import tkinter as tk
from tkinter import ttk
import time
import threading
import requests
import urllib3
import yaml
import paramiko
from concurrent.futures import ThreadPoolExecutor
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import logging

logging.basicConfig(
    filename='mesh_monitor.log',
    level=logging.INFO,
    format='%(asctime)s:%(levelname)s:%(message)s'
)

cpu_history = {}

# Add console handler
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s:%(levelname)s:%(message)s')
console_handler.setFormatter(formatter)
logging.getLogger('').addHandler(console_handler)

# Disable SSL warnings (local testing only)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ===== Load Configuration =====
with open("config.yaml", 'r') as file:
    config = yaml.safe_load(file)

# ===== Network Mesh Interfaces (API polled) =====
NETWORK_INTERFACES = config['network_mesh_interface']

interface_states = {
    iface_name: {
        'connected': False,
        'last_auth_attempt': 0,
        'auth_retry_interval': 30
    } 
    for iface_name in NETWORK_INTERFACES
}

# ===== Device Interface Mappings (MAC → info) =====
DEVICES = config['devices_interface']

# ===== Credentials =====
API_CREDENTIALS = config['credentials']['api']
SSH_CREDENTIALS = {
    device_name.split('_')[0]: creds
    for device_name, creds in config['credentials'].items()
    if device_name.endswith('_ssh')
}

# ===== SSH Commands =====
MONITOR_COMMANDS = config['ssh_commands']

# ===== Initialize Sessions per Mesh Interface =====
sessions = {}
for iface_name, iface_config in NETWORK_INTERFACES.items():
    session = requests.Session()
    retry = Retry(
        total=3,
        backoff_factor=0.3,
        status_forcelist=(500, 502, 504),
        allowed_methods=["POST"]
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    session.verify = False  # For local networks only
    sessions[iface_name] = {
        'session': session,
        'api_url': iface_config['api_url'],
        'wifi_interface': iface_config['wifi_interface'],
        'refresh_interval': iface_config['refresh_interval'],
        'token': None
    }
    
# ===== Sort values =====
SORT_VALUES = config['screen_sort']

# ===== Global Helper (MAC to device info) =====
MAC_TO_DEVICE = {mac.lower(): info for mac, info in DEVICES.items()}

# 1) AUTHENTICATE TO MESH (API)
def authenticate(iface_name):
    iface = sessions[iface_name]
    current_time = time.time()
    
    if (
        not interface_states[iface_name]['connected']
        and (current_time - interface_states[iface_name]['last_auth_attempt'])
           < interface_states[iface_name]['auth_retry_interval']
    ):
        return False

    interface_states[iface_name]['last_auth_attempt'] = current_time

    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "call",
        "params": [
            "00000000000000000000000000000000",
            "session",
            "login",
            {
                "username": API_CREDENTIALS['username'],
                "password": API_CREDENTIALS['password']
            }
        ]
    }

    try:
        response = iface['session'].post(iface['api_url'], json=payload)
        response.raise_for_status()
        result = response.json()
        if 'result' in result and result['result'][0] == 0:
            iface['token'] = result['result'][1]['ubus_rpc_session']
            interface_states[iface_name]['connected'] = True
            logging.info(f"Authenticated successfully with {iface_name}.")
            return True
        else:
            interface_states[iface_name]['connected'] = False
            logging.error(f"Authentication failed for {iface_name}: {result}")
            return False
    except requests.exceptions.ConnectionError:
        interface_states[iface_name]['connected'] = False
        logging.error(f"Controller unreachable for {iface_name}.")
        return False
    except Exception as e:
        interface_states[iface_name]['connected'] = False
        logging.error(f"Error during authentication for {iface_name}: {e}")
        return False

# 2) FETCH DEVICE ASSOCIATIONS FROM MESH (API)
def fetch_data(iface_name):
    iface = sessions[iface_name]
    if iface['token'] is None:
        logging.warning(f"Token not available for {iface_name}. Abort fetch.")
        return []
    
    payload = { 
        "jsonrpc": "2.0",
        "id": 1,
        "method": "call",
        "params": [
            iface['token'],
            "iwinfo",
            "assoclist",
            {
                "device": iface['wifi_interface']
            }
        ]
    }
    
    try:
        response_status = iface['session'].post(iface['api_url'], json=payload)
        response_status.raise_for_status()
        result_status = response_status.json()
        if 'result' in result_status and result_status['result'][0] == 0:
            status_data = result_status['result'][1].get('results', [])
            logging.info(f"{iface_name} => {len(status_data)} device(s) associated.")
            return status_data
        else:
            logging.error(f"Failed to fetch data from {iface_name}: {result_status}")
            return []
    except requests.exceptions.ConnectionError:
        logging.error(f"Controller unreachable for {iface_name} during data fetch.")
        return []
    except Exception as e:
        logging.error(f"Error fetching data from {iface_name}: {e}")
        return []

# 3) SSH TO DEVICES (ROBOT/HUMAN-INTERFACE ONLY)
def get_system_info(device_name, ip):
    """
    Only valid if type = 'robot' or 'human_device_interface'.
    """
    creds = SSH_CREDENTIALS.get(device_name)
    if not creds:
        logging.error(f"No SSH credentials found for device={device_name}.")
        return {"cpu_float": 0.0, "disk": "N/A"}

    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            ip,
            username=creds['username'],
            password=creds['password'],
            timeout=creds.get('timeout', 2),
            banner_timeout=2000
        )

        system_info = {}
        for key, command in MONITOR_COMMANDS.items():
            stdin, stdout, stderr = client.exec_command(command)
            output = stdout.read().decode().strip()
            system_info[key] = output
            print(f"[{device_name}] Command={command}, Output={output}")

        client.close()

        # The CPU usage is like "3.4%". Convert to float for rolling average
        cpu_str = system_info.get('cpu', '0').replace('%','')
        try:
            cpu_float = float(cpu_str)
        except:
            cpu_float = 0.0

        return {
            "cpu_float": cpu_float,
            "disk": system_info.get('disk', 'N/A'),
            "voltage": system_info.get('voltage', 'N/A')
        }

    except Exception as e:
        logging.error(f"Error retrieving system info from {device_name} ({ip}): {e}")
        return {"cpu_float": 0.0, "disk": "N/A", "voltage": "N/A"}


# 4) TKINTER TABLES
def create_table_1(frame):
    """
    Upper table: includes a 'Mesh Controller' column
    to show belongs_to, plus device metrics.
    """
    global table_1
    for widget in frame.winfo_children():
        widget.destroy()
    
    table_1 = ttk.Treeview(
        frame, 
        # -------------- NOTE: ADDED A NEW COLUMN HERE ---------------
        columns=(
            "Mesh Controller", 
            "Device", 
            "Signal Strength", 
            "Connected Time", 
            "Throughput", 
            "Bandwidth"
        ), 
        show="headings"
    )
        
    # Define headers
    table_1.heading("Mesh Controller", text="Mesh Controller")
    table_1.heading("Device",          text="Device")
    table_1.heading("Signal Strength", text="Signal Strength")
    table_1.heading("Connected Time",  text="Connected Time")
    table_1.heading("Throughput",      text="Throughput")
    table_1.heading("Bandwidth",       text="Bandwidth")
    
    # Define column widths
    table_1.column("Mesh Controller", width=120, anchor="center")
    table_1.column("Device",          width=150, anchor="center")
    table_1.column("Signal Strength", width=150, anchor="center")
    table_1.column("Connected Time",  width=150, anchor="center")
    table_1.column("Throughput",      width=150, anchor="center")
    table_1.column("Bandwidth",       width=150, anchor="center")
    
    table_1.pack(fill="both", expand=True)

def create_table_2(frame):
    global table_2
    for widget in frame.winfo_children():
        widget.destroy()

    columns = ["Parameter"]
    table_2 = ttk.Treeview(frame, columns=columns, show="headings")

    table_2.heading("Parameter", text="Parameter")
    table_2.column("Parameter", width=150, anchor="center")

    # Insert rows for CPU, Disk, and Voltage
    table_2.insert("", "end", values=["CPU Usage"])
    table_2.insert("", "end", values=["Disk Space"])
    table_2.insert("", "end", values=["Voltage"]) 

    table_2.pack(fill="both", expand=True)


def update_table_2(name, cpu_usage, disk_space, voltage):
    """
    Update pivot table_2 with CPU & Disk usage & Voltage for a specific device.
    """
    current_columns = table_2["columns"]
    if name not in current_columns:
        new_columns = list(current_columns) + [str(name)]
        table_2["columns"] = new_columns
        for col in new_columns:
            table_2.heading(col, text=col)
            table_2.column(col, width=120, anchor="center")

    rows = {table_2.item(item, "values")[0]: item for item in table_2.get_children()}

    def set_cell(row_label, value):
        row_id = rows.get(row_label)
        if row_id:
            table_2.set(row_id, name, str(value))

    set_cell("CPU Usage",  cpu_usage)
    set_cell("Disk Space", disk_space)
    set_cell("Voltage",    voltage)
    
def sort_values(list_value):
    column = SORT_VALUES["value"]
    order = SORT_VALUES["order"]
    if column=="signal" and order=="ascending":
         return sorted(list_value, key=lambda x: x[2])  
    else:
        logging.info(f"Values not sorted!")
        return list_value
    
# 5) MAIN LOOP: GET DATA → DISPLAY
def update_data():
    # Clear top table so we can repopulate
    for item in table_1.get_children():
        table_1.delete(item)
        
    # Initialize an empty list to store MAC addresses and values
    mac_list = []
    values_list = []

    # Iterate over each mesh controller
    for iface_name, iface_config in NETWORK_INTERFACES.items():
        # Authenticate if necessary
        if not interface_states[iface_name]['connected']:
            authenticate(iface_name)

        # If we have a valid session token, fetch associated devices
        if interface_states[iface_name]['connected']:
            devices_list = fetch_data(iface_name)
            if not devices_list:
                continue

            # Create a thread pool for parallel SSH calls
            with ThreadPoolExecutor(max_workers=10) as executor:
                futures_map = {}
                is_new_mac = False  # Default value

                # For each device found in assoclist
                for device_data in devices_list:
                    mac = device_data.get('mac', '').lower()
                    logging.info(f"Device data: {device_data}")

                    device_info = MAC_TO_DEVICE.get(mac)
                    logging.info(f"Device info: {device_info}")
                    if not device_info:
                        # Skip if not in our config
                        continue
                        
                    # Check if MAC address is already in the list
                    if mac in mac_list:
                        if SORT_VALUES["one_device"]:
                            is_new_mac = False  # MAC already exists
                        else:
                            is_new_mac = True
                    else:
                        is_new_mac = True   # New MAC found
                        mac_list.append(mac)  # Add it to the list

                    logging.info(f"MAC {mac} is {'new' if is_new_mac else 'already seen'}")

                    # If device is a robot or human_device_interface, do SSH polling
                    dev_type = device_info.get('type', 'unknown')
                    if dev_type in ["robot", "human_device_interface"] and is_new_mac:
                        name = device_info['name']
                        ip_address = device_info['ip']
                        future = executor.submit(get_system_info, name, ip_address)
                        futures_map[future] = (name, device_data, dev_type)

                # Process SSH results
                for future in futures_map:
                    name, device_data, dev_type = futures_map[future]
                    result_info = future.result()
                    
                    cpu_val    = result_info.get('cpu_float', 0.0)
                    disk_space = result_info.get('disk', 'N/A')
                    
                    # Voltage only for robots
                    if dev_type == "robot":
                        voltage = result_info.get('voltage', 'N/A')
                    else:
                        voltage = "N/A"

                    # Update rolling average CPU usage
                    global cpu_history
                    if name not in cpu_history:
                        cpu_history[name] = []
                    cpu_history[name].append(cpu_val)
                    
                    # Keep up to 5 entries for smoothing
                    if len(cpu_history[name]) > 5:
                        cpu_history[name].pop(0)
                    
                    avg_cpu = sum(cpu_history[name]) / len(cpu_history[name])
                    avg_cpu_str = f"{avg_cpu:.1f}%"

                    # Prepare data for top table
                    belongs_to     = device_info.get('belongs_to', 'N/A') if device_info else 'N/A'
                    signal         = f"{device_data.get('signal', 'N/A')} dBm"
                    connected_time = f"{device_data.get('connected_time', 'N/A')} s"
                    throughput     = f"{device_data.get('thr', 0)/1000:.2f} Mbps"
                    bandwidth      = f"{device_data.get('rx', {}).get('rate', 0)/1000:.2f} Mbps"
                    
                    values_list.append([belongs_to,name,signal,connected_time,throughput,bandwidth,name, avg_cpu_str, disk_space, voltage])
     
    if len(values_list)>=1:  
        # Sorting by the "signal" column (index 2), in ascending order
        values_list_sorted = sort_values(values_list)   
        
        for values_device in values_list_sorted:             
            # Insert row into Table 1
            table_1.insert(
                 "", "end", 
                 values=[
                    values_device[0],
                    values_device[1],
                    values_device[2],
                    values_device[3],
                    values_device[4],
                    values_device[5]
                 ]
            )

            # Update pivot table (Table 2) with CPU, Disk, Voltage
            update_table_2(values_device[6], values_device[7], values_device[8], values_device[9])

    # Schedule next refresh
    refresh_ms = list(NETWORK_INTERFACES.values())[0]['refresh_interval']
    root.after(refresh_ms, update_data)
    
# 6) TKINTER GUI SETUP
if __name__ == "__main__":
    # Initial authentication
    for iface_name in NETWORK_INTERFACES:
        authenticate(iface_name)

    # Main GUI window
    root = tk.Tk()
    root.title("Mesh Network Monitoring")
    root.geometry("1200x600")

    # Top frame (Table 1)
    frame_1 = ttk.Frame(root)
    frame_1.pack(fill="both", expand=True, padx=10, pady=5)
    create_table_1(frame_1)
    
    # Bottom frame (Table 2)
    frame_2 = ttk.Frame(root)
    frame_2.pack(fill="both", expand=True, padx=10, pady=5)
    create_table_2(frame_2)

    # Start periodic updates
    update_data()

    # Tk main loop
    root.mainloop()
