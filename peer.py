import socket
import threading
import requests
import os
import time  # Import time for sleep functionality
import random  # Import random for selecting peers
import struct

TRACKER_URL = "http://127.0.0.1:5000"
BUFFER_SIZE = 65565  # chunks
TOTAL_CHUNKS = 20  # Total number of chunks

def calculate_checksum(packet):
    checksum = 0
    for index in range(0, len(packet), 2):
        if index + 1 < len(packet):
            chunk = struct.unpack('!H', packet[index:index + 2])[0]
        else:
            chunk = struct.unpack('!H', packet[index:index + 1] + b'\x00')[0]
        checksum += chunk
    checksum = (checksum >> 16) + (checksum & 0xFFFF)
    return ~checksum & 0xFFFF

def validate_checksum(packet):
    """
    Calculate packet's checksum to see if it's been corrupted

    :param packet: packet to validate
    :return: True if packet hasn't been corrupted, False otherwise
    """
    received_checksum = struct.unpack('!H', packet[0:2])[0]
    packet_without_checksum = struct.pack('!H', 0) + packet[2:]

    checksum = 0
    for index in range(0, len(packet_without_checksum), 2):
        if index + 1 < len(packet_without_checksum):
            chunk = struct.unpack('!H', packet_without_checksum[index:index + 2])[0]
        else:
            chunk = struct.unpack('!H', packet_without_checksum[index:index + 1] + b'\x00')[0]
        checksum += chunk
    checksum = (checksum >> 16) + (checksum & 0xFFFF)
    checksum = ~checksum & 0xFFFF

    if checksum == received_checksum:
        return True
    else:
        print(f"Checksum is invalid: {checksum}. chunk is: {packet[2:]}")
        return False

class Peer:
    def __init__(self, peer_id, port, files, is_origin=False):
        self.peer_id = peer_id
        self.ip = self.get_local_ip()
        self.port = port
        self.files = files  # Example: {"file1.txt": [0, 1, 2]}
        self.is_origin = is_origin
        self.chunk_dir = f"chunks/{self.peer_id}"  # Directory to store chunks
        os.makedirs(self.chunk_dir, exist_ok=True)  # Create directory if it doesn't exist
        
        if self.is_origin:
            self.create_chunks()  # Create chunks for the origin peer

    def create_chunks(self):
        """ Create 20 chunks for the origin peer from file1.txt """
        # Read the content of the original file
        with open("file1.txt", "r") as original_file:
            content = original_file.read()
        
        # Calculate the size of each chunk
        chunk_size = len(content) // TOTAL_CHUNKS
        
        for chunk_id in range(TOTAL_CHUNKS):
            start_index = chunk_id * chunk_size
            # For the last chunk, take the remainder of the content
            if chunk_id == TOTAL_CHUNKS - 1:
                chunk_data = content[start_index:]  # Take the rest of the content
            else:
                chunk_data = content[start_index:start_index + chunk_size]
            
            # Write the chunk data to the corresponding chunk file
            with open(os.path.join(self.chunk_dir, f"{chunk_id}.chunk"), "wb") as f:
                f.write(chunk_data.encode('utf-8'))
        
        self.files["file1.txt"] = list(range(TOTAL_CHUNKS))  # Update files to reflect all chunks

    def get_local_ip(self):
        """ Get local IP address """
        return socket.gethostbyname(socket.gethostname())

    def register(self):
        """ Register this peer with the tracker """
        data = {
            "peer_id": self.peer_id,
            "ip": self.ip,
            "port": self.port,
            "files": self.files
        }
        print(f"Registering peer {self.peer_id} with tracker at {TRACKER_URL}/register")
        response = requests.post(f"{TRACKER_URL}/register", json=data)
        
        if response.status_code == 200:
            print(f"Peer {self.peer_id} registered successfully.")
            # Update local files based on response from tracker
            self.update_files_from_tracker(response.json().get("peers", {}))
            self.update_chunk_availability()  # Now update chunk availability
        else:
            print(f"Failed to register peer {self.peer_id}: {response.text}")

    def update_chunk_availability(self):
        """ Notify the tracker about the chunks this peer has """
        available_chunks = {}
        
        # If this is the origin peer, report based on its files attribute
        if self.is_origin:
            available_chunks = {filename: chunk_ids for filename, chunk_ids in self.files.items()}  # Ensure correct format
            print(f"Origin peer {self.peer_id} has chunks: {available_chunks}")
        else:
            # List available chunks in the peer's directory for non-origin peers
            for filename in os.listdir(self.chunk_dir):
                if filename.endswith('.chunk'):  # Assuming chunks are stored with .chunk extension
                    chunk_id = int(filename.split('.')[0])  # Extract chunk ID from filename
                    # Report in the same format as the origin peer
                    if "file1.txt" not in available_chunks:
                        available_chunks["file1.txt"] = []  # Initialize the list if not present
                    available_chunks["file1.txt"].append(chunk_id)  # Add chunk ID to the list

            print(f"Non-origin peer {self.peer_id} has chunks: {available_chunks}")

        data = {
            "peer_id": self.peer_id,
            "files": available_chunks  # Report available chunks
        }
        print(f"Peer {self.peer_id} updating chunk availability with tracker: {available_chunks}")
        response = requests.post(f"{TRACKER_URL}/update", json=data)
        print(f"Response from tracker for peer {self.peer_id}: {response.status_code} - {response.text}")

    def update_files_from_tracker(self, peers):
        """ Update local files based on available peers """
        for peer_id, info in peers.items():
            if peer_id != self.peer_id:  # Don't update from self
                print(f"Peer {self.peer_id} sees that {peer_id} has files: {info['files']}")
                # Here you can implement logic to update local files based on what peers have
                for filename, chunk_ids in info['files'].items():
                    if filename not in self.files:
                        self.files[filename] = []
                    self.files[filename].extend(chunk_ids)  # Add new chunk IDs to the local files
                print(f"Updated local files for peer {self.peer_id}: {self.files}")

    def start_server(self):
        """ Start TCP server to serve file chunks """
        print(f"Starting server for peer {self.peer_id}...")
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind((self.ip, self.port))
        server_socket.listen(5)
        print(f"Peer {self.peer_id} listening on {self.ip}:{self.port}")

        while True:
            client_socket, addr = server_socket.accept()
            print(f"Peer {self.peer_id} accepted connection from {addr}")
            threading.Thread(target=self.handle_client, args=(client_socket,)).start()

    def handle_client(self, client_socket):
        """ Handle incoming peer requests for file chunks """
        request = client_socket.recv(1024).decode()
        print(f"Received request: {request} from {client_socket.getpeername()}")
        filename, chunk_id = request.split(" ")
        chunk_id = int(chunk_id)

        if filename in self.files and chunk_id in self.files[filename]:
            print(f"Peer {self.peer_id} is sending chunk {chunk_id} of {filename} to {client_socket.getpeername()}.")
            with open(os.path.join(self.chunk_dir, f"{chunk_id}.chunk"), "rb") as f:
                chunk_data = f.read() # Read the content of the chunk file
                initial_packet = struct.pack('!H', 0) + chunk_data
                checksum = calculate_checksum(initial_packet)
                packet = struct.pack('!H', checksum) + chunk_data
                client_socket.sendall(packet)  # Send the chunk data to the requesting peer
            print(f"Peer {self.peer_id} sent chunk {chunk_id} of {filename} to {client_socket.getpeername()}.")
        else:
            print(f"ERROR: Chunk {chunk_id} of {filename} not found for peer {self.peer_id}.")
            client_socket.sendall(b"ERROR: Chunk not found")

        client_socket.close()

    def request_chunk(self, peer_ip, peer_port, filename, chunk_id):
        """ Request a file chunk from another peer """
        print(f"Peer {self.peer_id} requesting chunk {chunk_id} of {filename} from {peer_ip}:{peer_port}.")
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((peer_ip, peer_port))
        client_socket.send(f"{filename} {chunk_id}".encode())
        client_socket.settimeout(1)

        try:
            chunk = client_socket.recv(BUFFER_SIZE)

            if not validate_checksum(chunk):
                print(f"Peer {self.peer_id} received CORRUPTED chunk {chunk_id} of {filename} from {peer_ip}:{peer_port}.")
            elif b"ERROR" not in chunk:
                print(f"Peer {self.peer_id} received chunk {chunk_id} of {filename} from {peer_ip}:{peer_port}, saving to file.")
                # Save chunk to the peer's directory
                with open(os.path.join(self.chunk_dir, f"{chunk_id}.chunk"), "wb") as f:
                    f.write(chunk[2:])
                print(f"Peer {self.peer_id} saved chunk {chunk_id} of {filename} successfully.")
            else:
                print(f"Peer {self.peer_id} failed to receive chunk {chunk_id} of {filename} from {peer_ip}:{peer_port}.")
        except OSError:
            print(f"Peer {self.peer_id} TIMED OUT requesting chunk {chunk_id} of {filename} from {peer_ip}:{peer_port}.")
        finally:
            client_socket.close()

    def get_peers_for_file(self, filename, chunk_id):
        """ Ask tracker for available peers with the requested file chunk """
        print(f"Requesting available peers for {filename} chunk {chunk_id} from tracker.")
        response = requests.get(f"{TRACKER_URL}/get_peers?filename={filename}&chunk_id={chunk_id}")
        peers = response.json().get("peers", {})
        print(f"Available peers for {filename} chunk {chunk_id}: {peers}")
        return peers

    def request_chunks_from_available_peers(self, filename, chunk_id):
        """ Request a file chunk from available peers using random selection """
        available_peers = self.get_peers_for_file(filename, chunk_id)
        peer_ids = list(available_peers.keys())
        if not peer_ids:
            print(f"No available peers for chunk {chunk_id} of {filename}.")
            return

        # Create a set to keep track of already selected peers
        selected_peers = set()

        # Randomly select a peer for each chunk request
        while len(selected_peers) < len(peer_ids):
            peer_id = random.choice(peer_ids)
            if peer_id not in selected_peers:
                peer_info = available_peers[peer_id]
                peer_ip = peer_info['ip']
                peer_port = peer_info['port']
                print(f"Peer {self.peer_id} attempting to request chunk {chunk_id} of {filename} from {peer_id} at {peer_ip}:{peer_port}.")
                self.request_chunk(peer_ip, peer_port, filename, chunk_id)
                selected_peers.add(peer_id)  # Mark this peer as selected

        print(f"Peer {self.peer_id} completed requests for chunk {chunk_id} of {filename}.")

    def switch_peer_connection(self):
        """ Randomly select a peer to connect with for chunk requests """
        available_peers = [peer for peer in peers if peer.peer_id != self.peer_id]  # Exclude self
        if available_peers:
            selected_peer = random.choice(available_peers)
            print(f"Peer {self.peer_id} will connect to {selected_peer.peer_id} for chunk requests.")
            return selected_peer
        else:
            print(f"No available peers to connect to for {self.peer_id}.")
            return None

    def request_chunks(self):
        for chunk_id in range(TOTAL_CHUNKS):  # Request all chunks (0 to 19)
            self.request_chunks_from_available_peers("file1.txt", chunk_id)
            self.update_chunk_availability()
            time.sleep(2)  # Wait before the next chunk request

if __name__ == "__main__":
    print('---------------------------------------------------------------------------------')
    peers = []
    threads = []
    for i in range(10):
        is_origin = (i == 0)  # First peer is the origin
        files = {"file1.txt": list(range(TOTAL_CHUNKS))} if is_origin else {}  # Only the origin peer has files
        peer = Peer(peer_id=f"peer{i+1}", port=6000 + i, files=files, is_origin=is_origin)
        peer.register()
        peers.append(peer)

        # Start TCP server for each peer in a separate thread
        thread1 = threading.Thread(target=peer.start_server, daemon=False)
        thread1.start()
        start_time = time.time()

        # Example: Request chunks from available peers for non-origin peers
        thread3 = threading.Thread(target=peer.request_chunks, daemon=False)
        thread3.start()