import os
import socket
from threading import Thread, Timer, Event  
from collections import defaultdict
import json
import logging
import warnings
import hashlib
from utils import *
from flask import Flask, request, jsonify
warnings.filterwarnings("ignore")
import time
import tkinter as tk
from tkinter import messagebox, scrolledtext
import requests
import bencodepy
from configs import CFG, Config
config = Config.from_json(CFG)

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

TRACKER_FOLDER = config.directory.tracker_db_dir
METAINFO_PATH = config.directory.tracker_db_dir + "metainfo.json"
NODES_INFO_PATH = config.directory.tracker_db_dir + "nodes.json"
FILES_INFO_PATH = config.directory.tracker_db_dir + "files.json"
ADDRESS_INFO_PATH = config.directory.tracker_db_dir + "addrs.json"

TRACKER_HOST = "192.168.0.112" #Change to tracker's IP address
TRACKER_PORT = 12345
TRACKER_PORT_LISTEN = 23456

class Tracker:
    def __init__(self, root):
        self.init_tracker_db()
        self.file_owners_list = defaultdict(list)
        self.metainfo_list = defaultdict(dict) 
        self.send_freq_list = defaultdict(int)
        self.has_informed_tracker = defaultdict(bool)
        self.users_online = 0
        if os.path.exists(ADDRESS_INFO_PATH):
            with open(ADDRESS_INFO_PATH, 'w') as f:
                json.dump({}, f)  
        self.root = root
        self.root.title("Tracker HTTP Interface")
        self.root.geometry("600x400")

        tk.Label(root, text="Tracker HTTP Interface", font=("Arial", 16)).pack(pady=10)
        tk.Button(root, text="Discover", command=self.discover).pack(pady=5)

        self.discover_text = scrolledtext.ScrolledText(root, width=70, height=10, state='disabled')
        self.discover_text.pack(pady=10)

        tk.Label(root, text="Node Ping", font=("Arial", 14)).pack(pady=10)
        self.node_id_entry = tk.Entry(root, width=10)
        self.node_id_entry.pack(pady=5)
        tk.Button(root, text="Ping Node", command=self.ping_node).pack(pady=5)
        self.ping_result = tk.Label(root, text="", font=("Arial", 12))
        self.ping_result.pack(pady=5)

    def init_tracker_db(self):
        if not os.path.exists(TRACKER_FOLDER):
            os.makedirs(TRACKER_FOLDER)
        if not os.path.exists(FILES_INFO_PATH):
            with open(FILES_INFO_PATH, 'w') as f:
                json.dump({}, f)
        if not os.path.exists(NODES_INFO_PATH):
            with open(NODES_INFO_PATH, 'w') as f:
                json.dump({}, f)
        if not os.path.exists(METAINFO_PATH):
            with open(METAINFO_PATH, 'w') as f:
                json.dump({}, f)
        if not os.path.exists(ADDRESS_INFO_PATH):
            with open(ADDRESS_INFO_PATH, 'w') as f:
                json.dump({}, f)
    
    def discover(self):
        try:
            with open(FILES_INFO_PATH, 'r') as file:
                data = json.load(file)
            self.discover_text.configure(state='normal')
            self.discover_text.delete(1.0, tk.END)
            self.discover_text.insert(tk.END, json.dumps(data, indent=4))
            self.discover_text.configure(state='disabled')
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load data: {e}")

    def ping_node(self):
        node_id = self.node_id_entry.get().strip()
        if not node_id:
            messagebox.showerror("Error", "Please enter a Node ID.")
            return
        try:
            if os.path.exists(ADDRESS_INFO_PATH):
                with open(ADDRESS_INFO_PATH, 'r') as addr_file:
                    addresses = json.load(addr_file)
                node_key = f'node{node_id}'  
                if node_key in addresses:
                    addr, port = addresses[node_key]
                    try:
                        response = requests.get(f"http://{addr}:{port}/ping", timeout=5)
                        if response.status_code == 200:
                            self.ping_result.config(text="Node is active")
                        else:
                            self.ping_result.config(text="Node is not active")
                    except requests.ConnectionError:
                        self.ping_result.config(text="Node is not active")
                else:
                    messagebox.showerror("Error", f"No address found for Node ID: {node_id}")
            else:
                messagebox.showerror("Error", "Address file not found.")
        except Exception as e:
            messagebox.showerror("Error", f"An unexpected error occurred: {e}")

    def write_torrent(self,torrent_data, filename):
        with open(filename, 'wb') as f:
            f.write(torrent_data)

    def add_file_owner(self, msg: dict): 
        decoded_torrent=bencodepy.decode(msg['torrent_data'].encode('latin1'))
        torrent_data=bencodepy.encode(decoded_torrent)
        info=decoded_torrent[b'info']
        infohash=hashlib.sha1(bencodepy.encode(info)).digest().hex()
        filename=info[b'name'].decode('utf-8')
        filesize=info[b'length']
        piece_length=info[b'piece length']
        pieces=info[b'pieces']
        entry = {
            'node_id': msg['node_id'],
            'addr': (msg['addr'][0], msg['listen_port']),
            'filename': filename,
            'filesize': filesize
        }
        metainfo={
            'filename': filename,
            'filesize': filesize,
            'piece_length': piece_length,
            'pieces': pieces.hex()
        }
        log_content = f"Node {msg['node_id']} owns {infohash} and is ready to send."
        logging.info(log_content)
        self.metainfo_list[infohash] = json.dumps(metainfo)
        if infohash not in self.file_owners_list:
            print(f"Infohash {infohash} not found in file_owners_list. Initializing it.")
            self.file_owners_list[infohash] = []
        self.file_owners_list[infohash].append(json.dumps(entry))
        self.file_owners_list[infohash] = list(set(self.file_owners_list[infohash]))
        print(self.send_freq_list)
        print(msg['node_id'])
        self.send_freq_list[msg['node_id']] += 1
        self.save_db_as_json()
        
    def update_db_enter(self, msg: dict, node_id: int):
        self.send_freq_list[node_id] = 0
        self.save_db_as_json()

    def search_file(self, msg: dict):
        log_content = f"Node {msg['node_id']} is searching for infohash: {msg['infohash']}"
        logging.info(log_content)
        matched_entries = []
        if msg['infohash'] in self.file_owners_list:
            for json_entry in self.file_owners_list[msg['infohash']]:
                entry = json.loads(json_entry)
                matched_entries.append((entry, self.send_freq_list[entry['node_id']]))
        else:
            logging.info(f"File {msg['filename']} not found in torrent.")
        filename=matched_entries[0][0]['filename']
        filesize=matched_entries[0][0]['filesize']
        response = {
            'node_id': msg['node_id'],
            'search_result': matched_entries,
            'filename': filename,
            'filesize': filesize,
            'infohash': msg['infohash']
        }
        return response

    def remove_node(self, node_id: int, addr: tuple):
        entry = json.dumps({
            'node_id': node_id,
            'addr': list(addr)
        })
        self.send_freq_list.pop(node_id, None)
        self.has_informed_tracker.pop((node_id, addr), None)
        for infohash in list(self.file_owners_list.keys()):
            updated_nodes = []
            for node_json in self.file_owners_list[infohash]:
                try:
                    node_entry = json.loads(node_json)
                except json.JSONDecodeError as e:
                    logging.error(f"Failed to decode node entry: {e}")
                    continue
                if node_entry.get('node_id') != node_id:
                    updated_nodes.append(node_json)
            if updated_nodes:
                self.file_owners_list[infohash] = updated_nodes
            else:
                del self.file_owners_list[infohash]
        self.save_db_as_json()

    def check_nodes_periodically(self, interval: int):
        alive_nodes_ids = set()
        dead_nodes_ids = set()
        for node, has_informed in list(self.has_informed_tracker.items()):
            node_id, node_addr = node
            if has_informed:
                self.has_informed_tracker[node] = False
                alive_nodes_ids.add(node_id)
            else:
                dead_nodes_ids.add(node_id)
                self.remove_node(node_id=node_id, addr=node_addr)

        if alive_nodes_ids or dead_nodes_ids:
            logging.info(f"Node(s) {list(alive_nodes_ids)} are alive, and node(s) {list(dead_nodes_ids)} have left.")
        Timer(interval, self.check_nodes_periodically, args=(interval,)).start()

    def save_db_as_json(self):
        if not os.path.exists(config.directory.tracker_db_dir):
            os.makedirs(config.directory.tracker_db_dir)
        with open(NODES_INFO_PATH, 'w') as nodes_json:
            json.dump(self.send_freq_list, nodes_json, indent=4)
        with open(FILES_INFO_PATH, 'w') as files_json:
            json.dump(self.file_owners_list, files_json, indent=4)
        with open(METAINFO_PATH, 'w') as meta_json:
            json.dump(self.metainfo_list, meta_json, indent=4)
    
    def format_filesize(self, filesize: int) -> str:
        for unit in ['B', 'KB', 'MB', 'GB']:
            if filesize < 1024:
                return f"{filesize:.2f} {unit}"
            filesize /= 1024

    def search_with_keyword(self, keyword: str) -> list:
        matched_files = []
        try:
            for infohash, metainfo in self.metainfo_list.items():
                metainfo = json.loads(metainfo)
                if keyword.lower() in metainfo['filename'].lower() :
                    filesize=self.format_filesize(metainfo['filesize'])
                    matched_files.append({
                        'infohash': infohash,
                        'filename': metainfo['filename'],
                        'filesize': filesize,
                        'piece_length': metainfo['piece_length'],
                        'pieces': metainfo['pieces']
                    })
        except Exception as e:
            logging.error(f"Error searching for keyword: {e}")
        return matched_files

    def handle_node_request(self, request):
        msg = request.json
        mode = msg['mode']
        if mode == 'OWN':
            self.add_file_owner(msg=msg)
            return {"status": "success", "message": "File owner added"}
        elif mode == 'EXIT': 
            addr=(msg['addr'][0], msg['listen_port'])
            self.remove_node(node_id=msg['node_id'], addr=tuple(addr))
            logging.info(f"Node {msg['node_id']} exited the torrent intentionally.")
            return {"status": "success", "message": "Node exited"}
        elif mode =='SEARCH':
            return self.search_with_keyword(msg['keyword'])
        elif mode == "TORRENT":
            return self.search_file(msg=msg)
        elif mode == 'ENTER':
            node_id=self.users_online+1
            self.users_online+=1
            self.update_db_enter(msg,node_id)
            addr = {f'node{node_id}': (msg['addr'][0], msg['listen_tracker_port'])}
            if os.path.exists(ADDRESS_INFO_PATH):
                with open(ADDRESS_INFO_PATH, 'r') as addrs_json:
                    addresses = json.load(addrs_json)
            else:
                addresses = {}
            addresses.update(addr)
            with open(ADDRESS_INFO_PATH, 'w') as addrs_json:
                json.dump(addresses, addrs_json, indent=4)
            return {"status": "success", "message": "Success enter torrent", "node_id": node_id}

    def run_flask(self):
        app = Flask(__name__)
        @app.route('/health', methods=['GET'])
        def health_check():
            return jsonify({"status": "ok"}), 200
        @app.route('/tracker', methods=['POST'])
        def tracker_route():
            logging.info("Received request from proxy at /tracker")
            response = self.handle_node_request(request)
            logging.info(f"Sending response: {response}")
            return jsonify(response)
        app.run(host=config.constants.TRACKER_ADDR[0], port=config.constants.TRACKER_ADDR[1])

    def run(self):
        logging.info("Tracker main started.")
        timer_thread =Thread(target=self.check_nodes_periodically, args=(config.constants.TRACKER_TIME_INTERVAL,), daemon=True)
        timer_thread.start()
        flask_thread = Thread(target=self.run_flask, daemon=True)
        flask_thread.start()
        self.root.mainloop()

if __name__ == '__main__':
    root = tk.Tk()
    tracker = Tracker(root)
    tracker.run()
