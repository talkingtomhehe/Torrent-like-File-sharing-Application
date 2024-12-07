import socket
import requests
import sys
import argparse
from threading import Thread, Timer
from operator import itemgetter
import os
import base64
import json
import time
import hashlib
from utils import *
import mmap
import warnings
import tkinter as tk
import shutil
from tkinter import messagebox, scrolledtext, filedialog
from flask import Flask, jsonify
import logging
import time  # Import time module
import bencodepy
warnings.filterwarnings("ignore")

from configs import CFG, Config
config = Config.from_json(CFG)

PROXY_ADDRESS = "http://192.168.0.112:12367/proxy" #change to tracker's IP

class Node:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("BitTorrent-like Network System")
        self.root.geometry("400x300")
        self.root.configure(bg="#f0f0f0")
        self.rcv_socket = None
        self.send_socket = None
        self.files = []
        self.is_in_send_mode = False
        self.downloaded_files = {}
        self.listen_port = None
        self.metainfo_list = {}
        self.file_entry_list = []  

        self.app = Flask(__name__)
        self.listen_tracker_port = generate_random_port()
        self.next_call = time.time()
        self.initialize_node()
        
        @self.app.route('/ping', methods=['GET'])
        def ping():
            return jsonify({"status": "active"}), 200
        self.root.mainloop()

    def get_local_ip(self):
        try:
            # Use Google's public DNS server to determine the local IP address
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(('8.8.8.8', 80))
            IP = s.getsockname()[0]
        except Exception:
            IP = '127.0.0.1'
        finally:
            s.close()
        return IP

    def run_flask(self): 
        peer_ip = self.get_local_ip()
        self.app.run(host=peer_ip, port=self.listen_tracker_port, debug=False, use_reloader=False)
 
    def initialize_node(self):
        for widget in self.root.winfo_children():
            widget.destroy()

        self.rcv_socket = self.set_socket(generate_random_port())
        self.send_socket = self.set_socket(generate_random_port())
        self.listen_port = self.send_socket.getsockname()[1]
        
        self.enter_torrent()
        self.show_main_screen()
        self.init_node_directory()
        
        flask_thread = Thread(target=self.run_flask)
        flask_thread.setDaemon(True)
        flask_thread.start()
        
        timer_thread = Thread(target=self.inform_tracker_periodically, args=(config.constants.NODE_TIME_INTERVAL,))
        timer_thread.setDaemon(True)
        timer_thread.start()

    def show_main_screen(self):
        self.root.geometry("800x800")
        self.root.configure(bg="#f0f0f0")

        main_frame = tk.Frame(self.root, bg="#f0f0f0")
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        header_frame = tk.Frame(main_frame, bg="#f0f0f0")
        header_frame.pack(fill=tk.X)

        header_frame.columnconfigure(0, weight=1)  
        header_frame.columnconfigure(1, weight=0)  
        header_frame.columnconfigure(2, weight=1)  

        node_label = 'Node ' + str(self.node_id)
        tk.Label(header_frame, text=node_label, font=("Arial", 16, "bold"), bg="#f0f0f0").grid(row=0, column=1)
        tk.Button(header_frame, text="Logout", command=self.exit_node).grid(row=0, column=2, padx=10, pady=10, sticky="e")

        # Section: Upload Panel
        upload_frame = tk.Frame(main_frame, bg="#d9eaf7", bd=1, relief=tk.RIDGE)
        upload_frame.pack(fill=tk.X, pady=0)
        tk.Label(upload_frame, text="Upload", font=("Arial", 12, "bold"), bg="#d9eaf7").pack(anchor="w", padx=10, pady=5)

        # Upload Panel Content
        upload_content = tk.Frame(upload_frame, bg="#d9eaf7")
        upload_content.pack(fill=tk.X, padx=10, pady=0)
        tk.Label(upload_content, text="File name:", bg="#d9eaf7").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.filename = tk.Entry(upload_content, width=40)
        self.filename.grid(row=0, column=1, padx=5, pady=5)
        tk.Button(upload_content, text="Upload", command=lambda: self.set_send_mode(self.filename.get())).grid(row=0, column=2, padx=5, pady=5)
        tk.Button(upload_content, text="Browse from computer", command=self.browse_file_upload).grid(row=0, column=3, padx=5, pady=5)

        # Section: Download Panel
        download_frame = tk.Frame(main_frame, bg="#d9eaf7", bd=1, relief=tk.RIDGE)
        download_frame.pack(fill=tk.X, pady=0)
        tk.Label(download_frame, text="Download", font=("Arial", 12, "bold"), bg="#d9eaf7").pack(anchor="w", padx=10, pady=5)

        # Download Panel Content
        download_content = tk.Frame(download_frame, bg="#d9eaf7")
        download_content.pack(fill=tk.X, padx=10, pady=0)
        tk.Label(download_content, text="Info hash:", bg="#d9eaf7").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.infohash = tk.Entry(download_content, width=40)
        self.infohash.grid(row=0, column=1, padx=5, pady=5)
        tk.Button(download_content, text="Browse .torrent file", command=self.browse_file_torrent).grid(row=0, column=2, padx=5, pady=5)
        tk.Button(download_content, text="Add queue download", command=lambda: self.add_to_queue(self.infohash.get())).grid(row=0, column=3, padx=5, pady=5)
        tk.Button(download_content, text="Download", command=self.set_download_mode, bg="green",
    fg="white").grid(row=0, column=4, padx=5, pady=5)

        # Section: Search Panel
        search_frame = tk.Frame(main_frame, bg="#d9eaf7", bd=1, relief=tk.RIDGE)
        search_frame.pack(fill=tk.X, pady=0)
        tk.Label(search_frame, text="Dont have .torrent file? Search infohash", font=("Arial", 12, "bold"), bg="#d9eaf7").pack(anchor="w", padx=10, pady=5)

        # Search Panel Content
        search_content = tk.Frame(search_frame, bg="#d9eaf7")
        search_content.pack(fill=tk.X, padx=10, pady=0)
        tk.Label(search_content, text="Keyword or filename:", bg="#d9eaf7").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.keyword = tk.Entry(search_content, width=40)
        self.keyword.grid(row=0, column=1, padx=5, pady=5)
        tk.Button(search_content, text="Search", command=lambda: self.search_file(self.keyword.get())).grid(row=0, column=2, padx=5, pady=5)

        # Section: Log Console
        log_frame = tk.Frame(main_frame, bg="#d9eaf7", bd=1, relief=tk.RIDGE)
        log_frame.pack(fill=tk.BOTH, expand=True, pady=0)
        tk.Label(log_frame, text="Log Console", font=("Arial", 12, "bold"), bg="#d9eaf7").pack(anchor="w", padx=10, pady=5)
        self.log_text = scrolledtext.ScrolledText(log_frame, width=160, height=5, state='disabled', font=("Consolas", 10))
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

    def log_message(self, message):
        current_time = time.time()
        if current_time - self.last_log_time >= self.log_delay:
            self.log_text.configure(state='normal')
            self.log_text.insert(tk.END, f"[Node {self.node_id}] {message}\n")
            self.log_text.configure(state='disabled')
            self.log_text.see(tk.END)
            self.last_log_time = current_time
            self.root.update_idletasks()
   
    def hash_filename(self, filename: str) -> str:
        return hashlib.sha256(filename.encode()).hexdigest()
    
    def hash_file(self, file_path: str, chunk_size: int = 8192) -> str:
        hasher = hashlib.sha256() 
        try:
            with open(file_path, 'rb') as f:
                while chunk := f.read(chunk_size):
                    hasher.update(chunk)  
            return hasher.hexdigest() 
        except FileNotFoundError:
            print(f"File not found: {file_path}")
            return None
        except Exception as e:
            print(f"An error occurred: {e}")
            return None
        
    def hash_meta_info(self, meta_info: dict) -> str:
        return hashlib.sha256(json.dumps(meta_info).encode()).hexdigest()

    def set_socket(self, port: int) -> socket.socket:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind((self.get_local_ip(), port)) 
        return sock
    
    def log_message(self, message):
        self.log_text.configure(state='normal')
        self.log_text.insert(tk.END, f"{message}\n")
        self.log_text.configure(state='disabled')
        self.log_text.see(tk.END)

    def register_node(self):
        node_id = self.node_id_entry.get()
        if node_id:
            self.enter_torrent()
            self.log_message(f"Node {node_id} registered successfully.")
        else:
            messagebox.showerror("Input Error", "Node ID is required.")

    def exit_node(self):
        self.exit_torrent()
        self.log_message(f"Node {self.node_id} exited successfully.")
        self.root.quit()
        sys.exit()

    def send_segment(self, sock: socket.socket, data: bytes, addr: tuple):
        try:
            sock.sendall(data)
        except OSError as e:
            if e.errno == 10056:  
                pass  
            else:
                raise e  

    def reassemble_file(self, chunks: list, file_path: str):
        with open(file_path, "wb+") as f:  
            for ch in chunks:
                if isinstance(ch, int):
                    ch = str(ch).encode()  
                elif isinstance(ch, str):
                    ch = ch.encode()  
                f.write(ch)
            f.flush()
            f.close()
    import json
    def split_file_to_chunks(self, file_path: str, rng: tuple) -> list:
        with open(file_path, "r+b") as f:
            file_size = os.path.getsize(file_path)
            if rng[0] < 0 or rng[1] > file_size or rng[0] > rng[1]:
                raise ValueError("Invalid range specified!")
            
            with mmap.mmap(f.fileno(), 0) as mm:
                mm_chunk = mm[rng[0]:rng[1]]
                piece_size = config.constants.CHUNK_PIECES_SIZE
                return [mm_chunk[p: p + piece_size] for p in range(0, len(mm_chunk), piece_size)]
            
    def send_chunk(self, conn, filename: str, rng: tuple, dest_node_id: int):
        file_path = f"{config.directory.node_files_dir}node{self.node_id}/{filename}"
        chunk_pieces = self.split_file_to_chunks(file_path=file_path, rng=rng)
        peer_address = conn.getpeername()
        print(f"Sending chunks to node {dest_node_id} at address {peer_address[0]}:{peer_address[1]}")
        
        def send_single_chunk(conn, chunk_data, idx, rng, filename, dest_node_id):
            try:
                chunk_encoded = base64.b64encode(chunk_data).decode() if isinstance(chunk_data, bytes) else chunk_data
                msg = {
                    "src_node_id": self.node_id,
                    "dest_node_id": dest_node_id,
                    "filename": filename,
                    "range": rng,
                    "idx": idx,
                    "chunk": chunk_encoded
                }
                conn.sendall(json.dumps(msg).encode())
            except Exception as e:
                self.log_message(f"[-] Error sending chunk {idx} of file {filename}: {e}")

        threads = []
        log_content=f"[+] Number of chunks to send: {len(chunk_pieces)}"
        self.log_message(log_content)
        for i, chunk in enumerate(chunk_pieces):
            idx = rng[0] + i * config.constants.CHUNK_PIECES_SIZE
            log_content=f"[+] Starting thread {i} for chunk {idx}"
            self.log_message(log_content)
            thread = Thread(
                target=send_single_chunk,
                args=(conn, chunk, idx, rng, filename, dest_node_id)
            )
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()
        log_content=f"[+] Number of threads created: {len(threads)}"
        self.log_message(log_content)

        end_msg = {
            "src_node_id": self.node_id,
            "dest_node_id": dest_node_id,
            "filename": filename,
            "range": rng,
            "idx": -1
        }
        conn.sendall(json.dumps(end_msg).encode())
        self.log_message(f"[+] All chunks of {filename} have been sent.")


    def handle_requests(self, conn, msg: str, addr: tuple):
        try:
            msg_dict = json.loads(msg)
        except json.JSONDecodeError:
            print(f"Error: Không thể chuyển đổi thông điệp thành JSON: {msg}")
            return
        
        if msg_dict.get("type") == "SIZE_REQUEST":
            self.tell_file_size(conn=conn, msg=msg_dict)
            print("Xử lý yêu cầu SIZE_REQUEST thành công")
        
        elif msg_dict.get("type") == "CHUNK_REQUEST":
            self.send_chunk(conn=conn, filename=msg_dict["filename"], rng=msg_dict["range"], dest_node_id=msg_dict["src_node_id"])
            print("Xử lý yêu cầu CHUNK_REQUEST thành công")
        
        else:
            print(f"Yêu cầu không hợp lệ: {msg}")

    def listen(self):
        self.send_socket.listen(5)
        print(f"Node {self.node_id} is now listening on port {self.send_socket.getsockname()[1]}")
        while True:
            conn, addr = self.send_socket.accept()
            print(f"Accepted connection from {addr}")

            data = conn.recv(config.constants.BUFFER_SIZE) 
            if not data:
                print("Không thể nhận được dữ liệu")
                break

            print(f"Received data: {data.decode()}")  
            self.handle_requests(conn=conn, msg=data.decode(), addr=addr) 

    def browse_file_upload(self):
        file_path = filedialog.askopenfilename(title="Select file to upload")
        filename = os.path.basename(file_path)
        des_path = f"{config.directory.node_files_dir}node{self.node_id}/{filename}"
        try:
            shutil.copy(file_path, des_path)
            self.files.append(filename)
        except Exception as e:
            print(f"Failed to copy file {filename} to {des_path}: {e}")
        file_size = os.path.getsize(des_path)
        meta_info = {
            'filename': filename,
            'filesize': file_size,
        }
        infohash, torrent_data = self.create_torrent_file(des_path, file_size)
        self.files.append(filename)
        self.metainfo_list[infohash] = meta_info
        self.set_send_mode(filename)

    def browse_file_torrent(self):
        file_path = filedialog.askopenfilename(title="Select .torrent file")
        try:
            with open(file_path, 'rb') as f:
                torrent_data = bencodepy.decode(f.read())
                infohash = hashlib.sha1(bencodepy.encode(torrent_data[b'info'])).digest().hex()
                self.add_to_queue(infohash)
        except Exception as e:
            print(f"Failed to read .torrent file: {e}")

    def create_torrent_file(self, file_path, file_size):
        chunk_size=config.constants.CHUNK_PIECES_SIZE
        num_pieces = (file_size+chunk_size-1)//chunk_size
        tracker_url =config.constants.TRACKER_ADDR[0]
        pieces=b''
        with open(file_path, 'rb') as f:
            for _ in range(num_pieces):
                piece_data = f.read(chunk_size)
                pieces += hashlib.sha1(piece_data).digest()
        info = {
            b'piece length': chunk_size,
            b'pieces': pieces,
            b'name': os.path.basename(file_path).encode('utf-8'),
            b'length': file_size
        }
        torrent_data = {
            b'announce': tracker_url.encode('utf-8'),
            b'info': info
        }
        torrent_path = file_path + '.torrent'
        with open(torrent_path, 'wb') as f:
            f.write(bencodepy.encode(torrent_data))
        infohash = hashlib.sha1(bencodepy.encode(info)).digest().hex()
        return infohash,torrent_data

    def set_send_mode(self, filename):
        self.fetch_owned_files()
        if filename not in self.files:
            self.log_message(f"You don't have {filename}")
            return
        file_path = f"{config.directory.node_files_dir}node{self.node_id}/{filename}"
        file_size = os.path.getsize(file_path)
        infohash,torrent_data = self.create_torrent_file(file_path, file_size)
        payload = {
            'node_id': self.node_id,
            'mode': 'OWN',
            "torrent_data":bencodepy.encode(torrent_data).decode('latin1'),
            'listen_port': self.listen_port,
        }
        
        response = requests.post(PROXY_ADDRESS, json=payload)
        if response.status_code == 200:
            self.log_message(f"[+] Sent metainfo of {filename} to tracker.")
        else:
            self.log_message(f"[-] Failed to sent metainfo of {filename} to tracker.")

        if self.is_in_send_mode:
            log_content = f"[-] Already in send mode!"
            self.log_message(log_content)
            return
        else:
            self.is_in_send_mode = True
            log_content = f"[+] Open listen port: {self.listen_port}"
            self.log_message(log_content)
            t = Thread(target=self.listen, args=())
            t.setDaemon(True)
            t.start()

    def ask_file_size(self, filename, file_owner):
        peer_ip = file_owner[0]['addr'][0]
        peer_port = file_owner[0]['addr'][1]
        
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((peer_ip, peer_port))
                request = {
                    "type": "SIZE_REQUEST",
                    "filename": filename
                }
                request_str = json.dumps(request)
                s.sendall(request_str.encode())
                file_size_data = s.recv(config.constants.BUFFER_SIZE)
                file_size_data = file_size_data.decode()
                if not file_size_data or not file_size_data.isdigit():
                    print(f"Error: Received invalid file size: {file_size_data}")
                    return -1
                return int(file_size_data)
        except Exception as e:
            print(f"Error during file size request: {e}")
            return -1

    def tell_file_size(self, conn, msg: dict):
        try:
            filename = msg["filename"]
            file_path = f"{config.directory.node_files_dir}node{self.node_id}/{filename}"
            file_size = os.path.getsize(file_path)
            response_msg = str(file_size).encode()
            conn.sendall(response_msg)
            print(f"Sent file size: {file_size} for file {filename}")
        except Exception as e:
            print(f"Error sending file size: {e}")

    def receive_chunk(self, filename: str, range: tuple, file_owner: tuple):
        dest_node = file_owner[0]
        request = {
            "type": "CHUNK_REQUEST",
            "src_node_id": self.node_id,
            "filename": filename,
            "range": range
        }
        request_str = json.dumps(request)
        temp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            temp_sock.connect(tuple(dest_node["addr"])) 
            temp_sock.sendall(request_str.encode())
            log_content = f"[+] Sent request for chunk {range} of {filename} to node {dest_node['node_id']} at {dest_node['addr']}"
            self.log_message(log_content)
            chunks_received = b""
            while True:
                data = temp_sock.recv(config.constants.BUFFER_SIZE)
                if not data:
                    break 
                chunks_received += data  
                try:
                    while True:
                        message_boundary = chunks_received.find(b"}") + 1
                        if message_boundary == 0:
                            break  
                        json_data = chunks_received[:message_boundary]
                        chunks_received = chunks_received[message_boundary:]
                        chunk_msg = json.loads(json_data.decode())

                        if chunk_msg["idx"] == -1:
                            log_content = f"[+] Finished receiving chunks for {filename} from node {dest_node['node_id']}"
                            self.log_message(log_content)
                            if temp_sock and not temp_sock._closed:
                                temp_sock.close()
                            return  
                        else: 
                            self.log_message(f"[+] Received chunk {chunk_msg['idx']} for {filename} from node {dest_node['node_id']}")

                        chunk_data = base64.b64decode(chunk_msg["chunk"]) if isinstance(chunk_msg["chunk"], str) else chunk_msg["chunk"]

                        chunk = {
                            "idx": chunk_msg["idx"],
                            "chunk": chunk_data
                        }
                        if filename not in self.downloaded_files:
                            self.downloaded_files[filename] = []
                        self.downloaded_files[filename].append(chunk) 

                except json.JSONDecodeError:
                    pass

            self.log_message(f"All chunks for {filename} have been received and saved.")
        except Exception as e:
            self.log_message(f"Error while receiving chunk: {e}")
        finally:
            if temp_sock and not temp_sock._closed:
                try:
                    temp_sock.close()  
                    self.log_message(f"Socket to node {dest_node['node_id']} closed successfully")
                except OSError as e:
                    self.log_message(f"Error closing socket: {e}")

    def sort_downloaded_chunks(self, filename: str) -> list:
        sorted_chunks = sorted(self.downloaded_files[filename], key=itemgetter("idx"))
        sorted_downloaded_chunks = [chunk["chunk"] for chunk in sorted_chunks]
        return sorted_downloaded_chunks

    def split_file_owners(self, file_owners: list, filename: str, file_size: int):
        owners = []
        for owner in file_owners:
            if owner[0]['node_id'] != self.node_id:
                owners.append(owner)
        if len(owners) == 0:
            log_content = f"No one has {filename}"
            self.log_message(f"No one has {filename}")
            return
        owners = sorted(owners, key=lambda x: x[1], reverse=True)
        to_be_used_owners = owners[:config.constants.MAX_SPLITTNES_RATE]
        start_time = time.time()
        step = file_size / len(to_be_used_owners)
        chunks_ranges = [(round(step*i), round(step*(i+1))) for i in range(len(to_be_used_owners))]

        self.downloaded_files[filename] = []
        neighboring_peers_threads = []
        for idx, obj in enumerate(to_be_used_owners):
            t = Thread(target=self.receive_chunk, args=(filename, chunks_ranges[idx], obj))
            t.setDaemon(True)
            t.start()
            neighboring_peers_threads.append(t)
        for t in neighboring_peers_threads:
            t.join()
        print(f"Number of threads created: {len(neighboring_peers_threads)}")
        log_content = f"[+] Downloaded all the chunks of {filename}. Sorting..."
        self.log_message(log_content)
        sorted_chunks = self.sort_downloaded_chunks(filename=filename)
        log_content = f"[+] Sorted all the chunks of {filename}"
        self.log_message(log_content)
        end_time = time.time()
        download_duration = end_time - start_time
        log_content = f"[+] Download finished. Time {download_duration} seconds"
        self.log_message(log_content)
        total_file = []
        file_path = f"{config.directory.node_files_dir}node{self.node_id}/{filename}"
        for chunk in sorted_chunks:
            total_file.append(chunk)
        self.reassemble_file(chunks=total_file, file_path=file_path)
        log_content = f"[+] Finished download. File saved at {file_path}. Opening port..."
        self.log_message(log_content)
        self.files.append(filename)
        self.set_send_mode(filename)
        
    def set_download_mode(self):
        for file in self.file_entry_list:
            thread = Thread(target=self.download_file, args=(file,))
            thread.daemon = True  
            thread.start()

    def format_search_output(self,list):
        output=''
        for file in list:
            output+=f"Filename: {file['filename']}\n"
            output+=f"Filesize: {file['filesize']}\n"
            output+=f"Infohash: {file['infohash']}\n"
            output+=f"Piece length: {file['piece_length']}\n"
            output+=f"Pieces hash: {file['pieces']}\n"
            output+="\n"
        return output
    
    def format_torrent_output(self,data):
        output=''
        output+=f"   Filename: {data['filename']}\n"
        output+=f"   Filesize: {data['filesize']}\n"
        output+=f"   Infohash: {data['infohash']}\n"
        output+="   Search Results:\n"
        for result in data['search_result']:
            output+=f"\tNode ID: {result[0]['node_id']}"
            output+=f" Address: {result[0]['addr']}\n"
        return output
    
    def download_file(self, infohash: str):
        if infohash in self.metainfo_list:
            log_content = f"You already have this file!"
            self.log_message(log_content)
            return
        else:
            log_content = f"[+] Start download file with infohash {infohash}. Searching in torrent..."
            self.log_message(log_content)
            tracker_response = self.find_owners(infohash)
            if tracker_response is None:
                self.log_message("No response from tracker!")
                return
            filename = tracker_response['filename']
            filesize=tracker_response['filesize']
            if 'search_result' in tracker_response:
                file_owners = tracker_response['search_result']
                self.split_file_owners(file_owners, filename, filesize)
            else:
                self.log_message("File not found in torrent!")
            if infohash in self.file_entry_list:
                self.file_entry_list.remove(infohash)

    def search_file(self, keyword:str):
        payload = {
            'mode': 'SEARCH',
            'keyword': keyword,
        }
        try:
            response = requests.post(PROXY_ADDRESS, json=payload)
            if response.status_code == 200:
                tracker_msg = response.json()  
                tracker_response=self.format_search_output(tracker_msg)
                self.log_message(f"[+] Tracker response:\n{tracker_response}")  
                return tracker_msg
            else:
                self.log_message(f"Failed to search torrent for {keyword}.")
                return {}
        except Exception as e:
            self.log_message(f"Error while searching torrent: {e}")
            return {}
        
    def find_owners(self, infohash: str):
        payload = {
            'node_id': self.node_id,
            'mode': 'TORRENT',
            'infohash': infohash,
        }
        try:
            response = requests.post(PROXY_ADDRESS, json=payload)
            if response.status_code == 200:
                tracker_msg = response.json()  
                tracker_response=self.format_torrent_output(tracker_msg)
                self.log_message(f"[+] Tracker response:\n{tracker_response}")  
                return tracker_msg
            else:
                self.log_message(f"[-] Failed to search torrent for {infohash}.")
                return {}
        except Exception as e:
            self.log_message(f"[-] Error while searching torrent: {e}")
            return {}       
        
    def add_to_queue(self, info_hash: str):
        self.fetch_owned_files()
        if (info_hash == ""):
            self.log_message("[-] Please enter a valid infohash!")
            return
        if info_hash not in self.file_entry_list:
            if info_hash in self.metainfo_list:
                self.log_message(f"[-] You already have this file!")
            else:
                self.file_entry_list.append(info_hash)
                self.log_message(f"[+] Added file with infohash {info_hash} to download queue.")

    def init_node_directory(self):
        node_files_dir = config.directory.node_files_dir + 'node' + str(self.node_id)
        if os.path.exists(node_files_dir):
            shutil.rmtree(node_files_dir)  
        os.makedirs(node_files_dir)  

    def fetch_owned_files(self):
        node_files_dir = config.directory.node_files_dir + 'node' + str(self.node_id)
        if os.path.exists(node_files_dir) and os.path.isdir(node_files_dir):
            for file_name in os.listdir(node_files_dir):
                file_path = os.path.join(node_files_dir, file_name)
                if file_name.endswith('.torrent'):  
                    continue
                if file_name in self.files and os.path.exists(file_path+'.torrent'):
                    continue
                if os.path.isfile(file_path):  
                    file_size = os.path.getsize(file_path)
                    infohash, torrent_data = self.create_torrent_file(file_path, file_size)
                    self.files.append(file_name)
                    meta_info = {
                        'filename': file_name,
                        'filesize': file_size,
                    }
                    self.metainfo_list[infohash] = meta_info
        else:
            os.makedirs(node_files_dir)
        return 

    def exit_torrent(self):
        payload = {
            'node_id': self.node_id,
            'mode': 'EXIT',
            'listen_port': self.listen_port
        }
        response = requests.post(PROXY_ADDRESS, json=payload)
        if response.status_code == 200:
            log_content = f"Successfully exited the torrent."
        else:
            log_content = f"Failed to exit the torrent."
        self.log_message(log_content)

    def enter_torrent(self):
        payload = {
            'mode': 'ENTER',
            'listen_tracker_port': self.listen_tracker_port
        }
        response = requests.post(PROXY_ADDRESS, json=payload)
        node_id = response.json()['node_id']
        self.node_id = node_id
        if response.status_code == 200:
            log_content = f"Successfully entered the torrent."
        else:
            log_content = f"Failed to enter the torrent."
        print(log_content)

    def inform_tracker_periodically(self, interval: int):
        log_content = f"Send alive request to tracker every {interval} seconds."
        payload = {
            'node_id': self.node_id,
            'mode': 'ALIVE'
        }
        requests.post(PROXY_ADDRESS, json=payload)
        self.next_call = self.next_call + interval
        Timer(self.next_call - time.time(), self.inform_tracker_periodically, args=(interval,)).start()

def run():
    node = Node()
    node.root.mainloop()
    
if __name__ == '__main__':
    run()
