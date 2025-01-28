#!/usr/bin/python3
import tkinter as tk
from tkinter import ttk
import time
import threading
import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Global variables for configuration
API_URL = "http://10.223.79.154/ubus"
USERNAME = "mesh"
PASSWORD = "macaroni"
TOKEN = None

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
                "device": "wlan0"  # Adjust the device name if necessary
            }
        ]
    }
    try:
        response = requests.post(API_URL, json=payload, verify=False)
        result = response.json()
        if 'result' in result and result['result'][0] == 0:
            return result['result'][1].get('results', [])
        else:
            print("Failed to fetch data:", result)
            return []
    except Exception as e:
        print("Error while fetching data:", e)
        return []

def update_table():
    """
    Fetch updated data and refresh the table.
    """
    for i in tree.get_children():
        tree.delete(i)  # Clear existing rows
    
    # Fetch new data
    new_data = fetch_data()
    
    # Populate the table with updated data
    for device in new_data:
        mac = device.get('mac', 'Unknown')
        if mac=="00:30:1A:3A:10:C2":
            name = "Castor"
        else:        
            name = mac
        signal = f"{device.get('signal', 'N/A')} dBm"
        connected_time = f"{device.get('connected_time', 'N/A')} s"
        throughput = f"{device.get('thr', {}) / 1000} Mbps"
        bandwidth = f"{device.get('rx', {}).get('rate', 0) / 1000} Mbps"  # Bandwidth from 'rx' rate
        tree.insert("", "end", values=(name, signal, connected_time, throughput, bandwidth))
    root.after(500, update_table)

# Authenticate with the API
authenticate()

# Create the main Tkinter window
root = tk.Tk()
root.title("Mesh Network Monitoring")
root.geometry("1000x300")

# Create a table (Treeview widget)
columns = ("MAC Address", "Signal Strength", "Connected Time", "Throughput", "Bandwidth")
tree = ttk.Treeview(root, columns=columns, show="headings")
tree.heading("MAC Address", text="MAC Address")
tree.heading("Signal Strength", text="Signal Strength")
tree.heading("Connected Time", text="Connected Time")
tree.heading("Throughput", text="Throughput")
tree.heading("Bandwidth", text="Bandwidth")
tree.pack(fill=tk.BOTH, expand=True)

# Start the update loop
update_table()

# Run the Tkinter main loop
root.mainloop()

