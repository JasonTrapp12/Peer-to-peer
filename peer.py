import socket
import threading
import requests
import os

TRACKER_URL = "http://127.0.0.1:5000"
BUFFER_SIZE = 512  # chunks

class Peer:
    def __init__(self, peer_id, port, files, is_origin=False):
        self.peer_id = peer_id
        self.ip = self.get_local_ip()
        self.port = port
        self.files = files  # Example: {"file1.txt": [0, 1, 2]}
        self.is_origin = is_origin
    
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
        requests.post(f"{TRACKER_URL}/register", json=data)
        print(f"Peer {self.peer_id} registered successfully.")
    
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
        print(f"Received request: {request}")
        filename, chunk_id = request.split(" ")
        chunk_id = int(chunk_id)

        if filename in self.files and chunk_id in self.files[filename]:
            print(f"Sending chunk {chunk_id} of {filename} to client.")
            with open(filename, "rb") as f:
                f.seek(chunk_id * BUFFER_SIZE)
                chunk = f.read(BUFFER_SIZE)
                client_socket.sendall(chunk)
        else:
            print(f"ERROR: Chunk {chunk_id} of {filename} not found.")
            client_socket.sendall(b"ERROR: Chunk not found")

        client_socket.close()

    def request_chunk(self, peer_ip, peer_port, filename, chunk_id):
        """ Request a file chunk from another peer """
        print(f"Requesting chunk {chunk_id} of {filename} from {peer_ip}:{peer_port}")
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((peer_ip, peer_port))
        client_socket.send(f"{filename} {chunk_id}".encode())

        chunk = client_socket.recv(BUFFER_SIZE)
        client_socket.close()

        if b"ERROR" not in chunk:
            print(f"Chunk {chunk_id} received from {peer_ip}:{peer_port}, saving to file.")
            # Save chunk to file
            with open(f"downloaded_{filename}", "ab") as f:
                f.seek(chunk_id * BUFFER_SIZE)
                f.write(chunk)
            print(f"Chunk {chunk_id} saved successfully.")
        else:
            print(f"Failed to receive chunk {chunk_id} from {peer_ip}:{peer_port}.")

    def get_peers_for_file(self, filename, chunk_id):
        """ Ask tracker for available peers with the requested file chunk """
        print(f"Requesting available peers for {filename} chunk {chunk_id} from tracker.")
        response = requests.get(f"{TRACKER_URL}/get_peers?filename={filename}&chunk_id={chunk_id}")
        peers = response.json().get("peers", {})
        print(f"Available peers for {filename} chunk {chunk_id}: {peers}")
        return peers

    def request_chunks_from_available_peers(self, filename, chunk_id):
        """ Request a file chunk from available peers """
        available_peers = self.get_peers_for_file(filename, chunk_id)
        for peer_id, peer_info in available_peers.items():
            peer_ip = peer_info['ip']
            peer_port = peer_info['port']
            print(f"Attempting to request chunk {chunk_id} of {filename} from {peer_id} at {peer_ip}:{peer_port}")
            self.request_chunk(peer_ip, peer_port, filename, chunk_id)


if __name__ == "__main__":
    peers = []
    for i in range(10):
        is_origin = (i == 0)  # First peer is the origin
        files = {"file1.txt": [0, 1, 2]} if is_origin else {}  # Only the origin peer has files
        peer = Peer(peer_id=f"peer{i+1}", port=6000 + i, files=files, is_origin=is_origin)
        peer.register()
        peers.append(peer)

        # Start TCP server for each peer in a separate thread
        threading.Thread(target=peer.start_server, daemon=True).start()

    # Example: Request chunks from available peers for non-origin peers
    for i in range(1, 10):  # Peers 2 to 10
        for chunk_id in range(3):  # Request all chunks (0, 1, 2)
            peers[i].request_chunks_from_available_peers("file1.txt", chunk_id)
