from flask import Flask, request, jsonify

app = Flask(__name__)

# Dictionary to track peers and the chunks they have
# {peer_id: {"ip": ip, "port": port, "files": {filename: [chunk_ids]}}}
peers = {}

@app.route('/register', methods=['POST'])
def register():
    """ Register a peer with the tracker """
    data = request.json
    peer_id = data['peer_id']
    peers[peer_id] = {
        "ip": data['ip'],
        "port": data['port'],
        "files": data['files']
    }
    print(f"Peer registered: {peer_id} at {data['ip']}:{data['port']} with files: {data['files']}")
    print(f"Current peers: {peers}")
    return jsonify({"message": "Peer registered", "peers": peers}), 200

@app.route('/get_peers', methods=['GET'])
def get_peers():
    """ Get a list of peers that have a specific file chunk """
    filename = request.args.get('filename')
    chunk_id = request.args.get('chunk_id')

    if not filename or chunk_id is None:
        print("Error: Filename and chunk_id required")
        return jsonify({"error": "Filename and chunk_id required"}), 400

    chunk_id = int(chunk_id)
    available_peers = {}

    for peer_id, info in peers.items():
        if filename in info['files'] and chunk_id in info['files'][filename]:
            available_peers[peer_id] = {
                "ip": info["ip"],
                "port": info["port"]
            }

    print(f"Available peers for {filename} chunk {chunk_id}: {available_peers}")
    return jsonify({"peers": available_peers}), 200

@app.route('/update', methods=['POST'])
def update():
    """ Update a peer's chunk list """
    data = request.json
    peer_id = data['peer_id']
    
    if peer_id not in peers:
        print(f"Error: Peer {peer_id} not found for update")
        return jsonify({"error": "Peer not found"}), 404
    
    peers[peer_id]['files'] = data['files']
    print(f"Updated peer {peer_id} with files: {data['files']}")
    return jsonify({"message": "Updated successfully"}), 200

@app.route('/deregister', methods=['POST'])
def deregister():
    """ Remove a peer from the tracker """
    data = request.json
    peer_id = data['peer_id']
    
    if peer_id in peers:
        del peers[peer_id]
        print(f"Peer {peer_id} deregistered")
    else:
        print(f"Peer {peer_id} not found for deregistration")
    
    return jsonify({"message": "Peer removed"}), 200

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000)
