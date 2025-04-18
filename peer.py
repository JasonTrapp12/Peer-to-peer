import socket
import threading
import requests
import os
import time
import random
import struct

TRACKER_URL = "http://127.0.0.1:5000"
BUFFER_SIZE = 65565
TOTAL_CHUNKS = 20  # Total number of chunks

def calculate_checksum(packet):
    """
    Calculate the checksum for a packet

    :param packet: packet to create checksum for
    :return: the checksum
    """
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
            chunk = struct.unpack('!H',
                                  packet_without_checksum[index:index + 2])[0]
        else:
            chunk = struct.unpack('!H',
                                  packet_without_checksum[index:index + 1]
                                  + b'\x00')[0]
        checksum += chunk
    checksum = (checksum >> 16) + (checksum & 0xFFFF)
    checksum = ~checksum & 0xFFFF

    if checksum == received_checksum:
        return True
    else:
        print(f"Checksum is invalid: {checksum}. chunk is: {packet[2:]}")
        return False

class Peer:
    """Class representing a peer"""
    def __init__(self, peer_id, port, files, filename, is_origin=False):
        """
        Peer constructor

        :param peer_id: uniquely identifies the peer
        :param port: port number for the peer
        :param files: files the peer has
        :param is_origin: True if peer is origin peer, False otherwise
        """
        self.peer_id = peer_id
        self.ip = self.get_local_ip()
        self.port = port
        self.files = files  # Example: {"file1.txt": [0, 1, 2]}
        self.is_origin = is_origin
        self.filename = filename

        # Directory to store chunks
        self.chunk_dir = f"chunks/{self.peer_id}"

        # Create directory if it doesn't exist
        os.makedirs(self.chunk_dir, exist_ok=True)
        
        if self.is_origin:
            self.create_chunks()  # Create chunks for the origin peer


    def create_chunks(self):
        """ Create 20 chunks for the origin peer from file1 """
        # Read the content of the original file
        with open(self.filename, "r") as original_file:
            content = original_file.read()
        
        # Calculate the size of each chunk
        chunk_size = len(content) // TOTAL_CHUNKS
        
        for chunk_id in range(TOTAL_CHUNKS):
            start_index = chunk_id * chunk_size
            # For the last chunk, take the remainder of the content
            if chunk_id == TOTAL_CHUNKS - 1:
                chunk_data = content[start_index:]
            else:
                chunk_data = content[start_index:start_index + chunk_size]
            
            # Write the chunk data to the corresponding chunk file
            with open(os.path.join(self.chunk_dir,
                                   f"{chunk_id}.chunk"), "wb") as f:
                f.write(chunk_data.encode('utf-8'))

        # Update files to reflect all chunks
        self.files[self.filename] = list(range(TOTAL_CHUNKS))

    def get_local_ip(self):
        """
        Get local IP address

        :return: IP address
        """
        return socket.gethostbyname(socket.gethostname())

    def register(self):
        """ Register this peer with the tracker """
        data = {
            "peer_id": self.peer_id,
            "ip": self.ip,
            "port": self.port,
            "files": self.files
        }
        print(f"Registering peer {self.peer_id} with tracker at "
              f"{TRACKER_URL}/register")
        response = requests.post(f"{TRACKER_URL}/register", json=data)
        
        if response.status_code == 200:
            print(f"Peer {self.peer_id} registered successfully.")
            # Update local files based on response from tracker
            self.update_files_from_tracker(response.json().get("peers", {}))
            self.update_chunk_availability()
        else:
            print(f"Failed to register peer {self.peer_id}: {response.text}")

    def update_chunk_availability(self):
        """ Notify the tracker about the chunks this peer has """
        available_chunks = {}
        
        # If this is the origin peer, report based on its files attribute
        if self.is_origin:
            available_chunks = {filename: chunk_ids for filename,
            chunk_ids in self.files.items()}
            print(f"Origin peer {self.peer_id} has chunks: "
                  f"{available_chunks}")
        else:
            # List available chunks in the peer's directory for
            # non-origin peers
            for filename in os.listdir(self.chunk_dir):
                if filename.endswith('.chunk'):
                    chunk_id = int(filename.split('.')[0])
                    if self.filename not in available_chunks:
                        # Initialize the list if not present
                        available_chunks[self.filename] = []
                    # Add chunk ID to the list
                    available_chunks[self.filename].append(chunk_id)

            print(f"Non-origin peer {self.peer_id} has chunks: "
                  f"{available_chunks}")

        data = {
            "peer_id": self.peer_id,
            "files": available_chunks  # Report available chunks
        }
        print(f"Peer {self.peer_id} updating chunk availability with "
              f"tracker: {available_chunks}")
        response = requests.post(f"{TRACKER_URL}/update", json=data)
        print(f"Response from tracker for peer {self.peer_id}: "
              f"{response.status_code} - {response.text}")


    def update_files_from_tracker(self, peers):
        """
        Update local files based on available peers

        :param peers: available peers
        """
        for peer_id, info in peers.items():
            if peer_id != self.peer_id:  # Don't update from self
                for filename, chunk_ids in info['files'].items():
                    if filename not in self.files:
                        self.files[filename] = []


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
            threading.Thread(target=self.handle_client,
                             args=(client_socket,)).start()

    def handle_client(self, client_socket):
        """
        Handle incoming peer requests for file chunks

        :param client_socket: socket to receive requests at
        """
        request = client_socket.recv(1024).decode()
        print(f"Received request: {request} from "
              f"{client_socket.getpeername()}")
        filename, chunk_id = request.split(" ")
        chunk_id = int(chunk_id)

        if filename in self.files and chunk_id in self.files[filename]:
            print(f"Peer {self.peer_id} is sending chunk {chunk_id} of "
                  f"{filename} to {client_socket.getpeername()}.")

            with open(os.path.join(self.chunk_dir,
                                   f"{chunk_id}.chunk"), "rb") as f:
                chunk_data = f.read() # Read the content of the chunk file
                initial_packet = struct.pack('!H', 0) + chunk_data
                checksum = calculate_checksum(initial_packet)
                packet = struct.pack('!H', checksum) + chunk_data

                # Send the chunk data to the requesting peer
                client_socket.sendall(packet)
            print(f"Peer {self.peer_id} sent chunk {chunk_id} of "
                  f"{filename} to {client_socket.getpeername()}.")
        else:
            print(f"ERROR: Chunk {chunk_id} of {filename} not found "
                  f"for peer {self.peer_id}.")
            client_socket.sendall(b"ERROR: Chunk not found")

        client_socket.close()

    def request_chunk(self, peer_ip, peer_port, filename, chunk_id):
        """
        Request a file chunk from another peer

        :param peer_ip: IP address of other peer
        :param peer_port: port number of other peer
        :param filename: filename to request chunk of
        :param chunk_id: ID of chunk to request
        """
        print(f"Peer {self.peer_id} requesting chunk {chunk_id} of "
              f"{filename} from {peer_ip}:{peer_port}.")
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((peer_ip, peer_port))
        client_socket.send(f"{filename} {chunk_id}".encode())
        client_socket.settimeout(1)

        try:
            chunk = client_socket.recv(BUFFER_SIZE)

            if not validate_checksum(chunk):
                print(f"Peer {self.peer_id} received CORRUPTED chunk "
                      f"{chunk_id} of {filename} from {peer_ip}:{peer_port}.")
            elif b"ERROR" not in chunk:
                print(f"Peer {self.peer_id} received chunk {chunk_id} of "
                      f"{filename} from {peer_ip}:{peer_port}, "
                      f"saving to file.")
                # Save chunk to the peer's directory
                with open(os.path.join(self.chunk_dir,
                                       f"{chunk_id}.chunk"), "wb") as f:
                    f.write(chunk[2:])
                print(f"Peer {self.peer_id} saved chunk {chunk_id} "
                      f"of {filename} successfully.")
            else:
                print(f"Peer {self.peer_id} failed to receive chunk "
                      f"{chunk_id} of {filename} from {peer_ip}:{peer_port}.")
        except OSError:
            print(f"Peer {self.peer_id} TIMED OUT requesting chunk "
                  f"{chunk_id} of {filename} from {peer_ip}:{peer_port}.")
        finally:
            client_socket.close()

    def get_peers_for_file(self, filename, chunk_id):
        """
        Ask tracker for available peers with the requested file chunk

        :param filename: filename to request chunks from
        :param chunk_id: ID of chunk to request
        :return: peers that have chunks of the desired file
        """
        print(f"Requesting available peers for {filename} chunk "
              f"{chunk_id} from tracker.")
        response = requests.get(f"{TRACKER_URL}/get_peers?filename="
                                f"{filename}&chunk_id={chunk_id}")
        peers = response.json().get("peers", {})
        print(f"Available peers for {filename} chunk {chunk_id}: {peers}")
        return peers

    def request_chunks(self):
        """Request chunks from peers until all chunks downloaded"""
        if self.is_origin:
            print(f"Peer {self.peer_id} is the origin and will not "
                  f"request chunks.")
            return

        while True:
            # Ask the tracker for the list of peers and chunk
            # availability
            response = requests.get(f"{TRACKER_URL}/get_peers?"
                                    f"filename={self.filename}")
            if response.status_code != 200:
                print(f"Peer {self.peer_id} failed to get peer info "
                      f"from tracker.")
                time.sleep(3)
                continue

            all_peers = response.json()

            local_chunks = set(self.files.get(self.filename, []))
            all_chunk_ids = set(all_peers['peers']['peer1']['chunks'])
            missing_chunks = all_chunk_ids - local_chunks

            if not missing_chunks:
                print(f"Peer {self.peer_id} has downloaded all chunks. Done!")
                break
            # Exclude only self from peer pool
            available_peer_ids = [peer_id for peer_id in all_peers['peers']
                                  if peer_id != self.peer_id]
            if not available_peer_ids:
                print(f"Peer {self.peer_id} found no other peers to "
                      f"request from.")
                time.sleep(3)
                continue

            selected_peer_id = random.choice(available_peer_ids)
            selected_peer_info = all_peers['peers'][selected_peer_id]
            peer_ip = selected_peer_info["ip"]
            peer_port = selected_peer_info["port"]
            their_chunks = set(selected_peer_info["chunks"])

            # Determine which chunks this peer has that we are missing
            needed_chunks = list(their_chunks & missing_chunks)

            if not needed_chunks:
                print(f"Peer {self.peer_id} selected {selected_peer_id}, "
                      f"but they have no needed chunks.")
                time.sleep(2)
                continue

            # Pick up to 5 chunks we still need that they have
            chunks_to_request = needed_chunks[:5]
            print(f"Peer {self.peer_id} requesting chunks {chunks_to_request}"
                  f" from {selected_peer_id} ({peer_ip}:{peer_port})")

            for chunk_id in chunks_to_request:
                self.request_chunk(peer_ip, peer_port, self.filename,
                                   chunk_id)
                if self.filename not in self.files:
                    self.files[self.filename] = []
                if chunk_id not in self.files[self.filename]:
                    self.files[self.filename].append(chunk_id)

            self.update_chunk_availability()

            delay = random.uniform(1, 3)
            print(f"Peer {self.peer_id} sleeping for {delay:.2f}s "
                  f"before next round.")
            time.sleep(delay)




if __name__ == "__main__":
    """Create 10 peers, and start threads for each"""
    print('-----------------------------------------------------------'
          '----------------------')

    filename = (input("Enter the filename to share (e.g., file1.txt): ")
                .strip())
    peers = []
    threads = []
    for i in range(10):
        is_origin = (i == 0)  # First peer is the origin

        # Only the origin peer has files
        files = {filename: list(range(TOTAL_CHUNKS))} if is_origin else {}

        peer = Peer(peer_id=f"peer{i+1}", port=6000 + i, files=files,
                    is_origin=is_origin, filename=filename)
        peer.register()
        peers.append(peer)

        # Start TCP server for each peer in a separate thread
        thread1 = threading.Thread(target=peer.start_server, daemon=False)
        thread1.start()
        start_time = time.time()

        # Request chunks from available peers for non-origin peers
        thread3 = threading.Thread(target=peer.request_chunks, daemon=False)
        thread3.start()