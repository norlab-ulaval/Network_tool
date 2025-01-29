#!/usr/bin/python3
import tkinter as tk
import paramiko
from tkinter import ttk
import time
import threading
import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

#00:30:1A:3A:10:C2  Castor  192.168.50.4, tommy: 10.223.50.101, haut: 10.223.50.100
#00:30:1A:3A:4F:9A  Base station

#######################################################################
########### Connexion to the mesh  
#######################################################################

def authenticate():
    """
    Authenticate with the API and retrieve a session token.
    """
    global TOKEN
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "call",
        "params": [
            "00000000000000000000000000000000",
            "session",
            "login",
            {
                "username": USERNAME,
                "password": PASSWORD
            }
        ]
    }
    try:
        response = requests.post(API_URL, json=payload, verify=False)
        result = response.json()
        if 'result' in result and result['result'][0] == 0:
            TOKEN = result['result'][1]['ubus_rpc_session']
            print("Authenticated successfully.")
        else:
            print("Authentication failed.")
    except Exception as e:
        print("Error during authentication:", e)

def fetch_data():
    """
    Fetch connected devices from the JSON-RPC API.
    """
    if TOKEN is None:
        print("Token is not available. Cannot fetch data.")
        return []

    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "call",
        "params": [
            TOKEN,
            "iwinfo",
            "assoclist",
            {
                "device": "wlan0"
            }
        ]
    }
    
    try:
        status_data = {}
        
        response_status = requests.post(API_URL, json=payload, verify=False)
        result_status = response_status.json()
        if 'result' in result_status and result_status['result'][0] == 0:
            status_data = result_status['result'][1].get('results', [])
        else:
            print("Failed to fetch data:", result)
        
        return status_data
            
            
    except Exception as e:
        print("Error while fetching data:", e)
        return []

def get_system_info(ip):
    """
    Retrieve CPU usage and available disk space from a device via SSH.
    """
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(ip, username=SSH_USERNAME, password=SSH_PW, timeout=1)

        # Command to get CPU usage
        stdin, stdout, stderr = client.exec_command("top -bn1 | grep 'Cpu(s)' | awk '{print $2+$4}'")
        cpu_usage = stdout.read().decode().strip()

        # Command to get available disk space
        stdin, stdout, stderr = client.exec_command("df -h / | tail -1 | awk '{print $4}'")
        disk_space = stdout.read().decode().strip()
        
        # Add more command if needed more data

        client.close()
        return {"cpu": f"{cpu_usage}%", "disk": disk_space}
    except Exception as e:
        print(f"Error retrieving system info from {ip}: {e}")
        return {"cpu": "N/A", "disk": "N/A"}       
        
#######################################################################
########### Display data
#######################################################################

def create_table_1(frame):
    """
    Create and update dynamically the table for each robot to monitor high level connection.
    """
    global table_1
    
    # Delete table if already existing
    for widget in frame.winfo_children():
        widget.destroy()
    
    table_1 = ttk.Treeview(frame, columns=("Robot", "Signal Strength", "Connected Time", "Throughput", "Bandwidth"), show="headings")
        
    # Define Header
    table_1.heading("Robot", text="Robot")
    table_1.heading("Signal Strength", text="Signal Strength")
    table_1.heading("Connected Time", text="Connected Time")
    table_1.heading("Throughput", text="Throughput")
    table_1.heading("Bandwidth", text="Bandwidth")
    
    # Display the table
    table_1.pack(fill="both", expand=True)

def create_table_2(frame):
    """
    Create and display the second table structure initially empty.
    It will be populated dynamically when data becomes available.
    """
    global table_2

    # Remove any existing widgets in the frame
    for widget in frame.winfo_children():
        widget.destroy()

    # Define the default column structure (only headers, no data)
    columns = [" "]  # Initially, only the first column exists

    # Create the table with column headers
    table_2 = ttk.Treeview(frame, columns=columns, show="headings")

    # Define column headers
    for col in columns:
        table_2.heading(col, text=col)
        table_2.column(col, width=120, anchor="center")

    # Insert empty rows for structure (CPU Usage & Memory rows)
    table_2.insert("", "end", values=["CPU Usage"])
    table_2.insert("", "end", values=["Memory"])

    # Display the table
    table_2.pack(fill="both", expand=True)
    
def update_data():
    """
    Update the data for both table.
    """
    
    # Delete data of current tables
    table_1.delete(*table_1.get_children())
    table_2.delete(*table_2.get_children())
    
    # Fetch new data
    new_data = fetch_data()
    
    # Check each new device found one the network
    for device in new_data:
        # Check name of the device based on the mac address
        name = 'Unknown'
        mac = device.get('mac', 'Unknown')
        if mac=="00:30:1A:3A:10:C2":
            name = "Castor"
            ip_adress = "192.168.50.4"
            
        # If device is known, check more advance information
        if name!='Unknown':
            # SSH communication to fetch more information
            system_info = get_system_info(ip_adress)
            combined_data = device | system_info
            
            # Fetch valuable data
            signal = f"{combined_data.get('signal', 'N/A')} dBm"
            connected_time = f"{combined_data.get('connected_time', 'N/A')} s"
            throughput = f"{combined_data.get('thr', {}) / 1000} Mbps"
            bandwidth = f"{combined_data.get('rx', {}).get('rate', 0) / 1000} Mbps"
            CPU_usage = f"{combined_data.get('CP_usage', 'N/A')} %"
            Memory_storage = f"{combined_data.get('Memory_storage', 'N/A')} %"
            
            values = [str(name), str(signal), str(connected_time), str(throughput), str(bandwidth), str(CPU_usage), str(Memory_storage)]
            
            # Push data into table 1
            table_1.insert("", "end", values=values[:5]) 

            # Get current column headers for table 2
            current_columns = table_2["columns"]

            # Add the robot column if it does not exist in table 2
            if name not in current_columns:
                new_columns = list(current_columns) + [str(name)]
                table_2["columns"] = new_columns

                # Update headers for the new columns
                for col in new_columns:
                    table_2.heading(col, text=col)
                    table_2.column(col, width=120, anchor="center")

            # Get existing data if there
            rows = {table_2.item(item, "values")[0]: item for item in table_2.get_children()}

            # Update or insert CPU Usage row
            if "CPU Usage" in rows:
                values = list(table_2.item(rows["CPU Usage"], "values"))
                values.append(str(CPU_usage))
                table_2.item(rows["CPU Usage"], values=values)
            else:
                table_2.insert("", "end", values=["CPU Usage", str(CPU_usage)])

            # Update or insert Memory row
            if "Memory" in rows:
                values = list(table_2.item(rows["Memory"], "values"))
                values.append(str(Memory_storage))
                table_2.item(rows["Memory"], values=values)
            else:
                table_2.insert("", "end", values=["Memory", str(Memory_storage)])

    # Reprogrammer l'actualisation
    root.after(500, update_data)


if __name__ == "__main__":

    # Global variables for configuration
    API_URL = "http://10.223.79.154/ubus"
    USERNAME = "mesh"
    PASSWORD = "macaroni"
    TOKEN = None
    SSH_USERNAME = "vaul"
    SSH_PW = "vaul"

    # Authenticate with the API for the token
    authenticate()

    # Create the main Tkinter window
    root = tk.Tk()
    root.title("Mesh Network Monitoring")
    root.geometry("1100x350")
    
    # Table 1 for high level connection information
    frame_1 = ttk.Frame(root)
    frame_1.pack(fill="both", expand=True, padx=10, pady=5)
    create_table_1(frame_1)
    
    # Table 2 for more detail information about the robot
    frame_2 = ttk.Frame(root)
    frame_2.pack(fill="both", expand=True, padx=10, pady=5)
    create_table_2(frame_2)

    # Start the update loop
    update_data()

    # Run the Tkinter main loop
    root.mainloop()

