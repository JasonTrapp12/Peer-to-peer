# P2P File Sharing System

This project implements a simple peer-to-peer (P2P) file sharing system with a central tracker using Python. Peers can share a file split into 20 chunks and download missing chunks from others.

## Components

- `server.py`: Tracker server that coordinates peer registration and chunk availability.
- `peer.py`: Peer node that can share and request file chunks.

---

## Prerequisites

- Python 3.x
- `requests` library for HTTP communication
- `Flask` for the tracker server

You can install Flask with:

```bash
pip install flask requests
```

---

## How to Run

### 1. Start the Tracker Server

```bash
python server.py
```

The tracker will start on `http://127.0.0.1:5000`.

---

### 2. Start the Peers

```bash
python peer.py
```

- You will be prompted to enter a filename (e.g., `file1.txt`).
- Make sure the file exists in the same directory before starting.
- The first peer (origin) splits the file into 20 chunks.
- All 10 peers (including the origin) will automatically register with the tracker, start a TCP server, and download missing chunks.

---