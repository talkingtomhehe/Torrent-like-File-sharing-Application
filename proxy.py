from flask import Flask, request, jsonify
import requests
from configs import CFG, Config

config = Config.from_json(CFG)
TRACKER_IP = config.constants.TRACKER_ADDR[0]
TRACKER_PORT = config.constants.TRACKER_ADDR[1]
TRACKER_URL = f"http://{TRACKER_IP}:{TRACKER_PORT}/tracker"

app = Flask(__name__)

@app.route('/proxy', methods=['POST'])
def handle_node_request():
    try:
        node_data = request.json
        client_ip = request.remote_addr
        client_port = request.environ.get('REMOTE_PORT')
        node_data['addr'] = (client_ip, int(client_port))
        tracker_response = requests.post(TRACKER_URL, json=node_data)
        tracker_data = tracker_response.json()
        return jsonify(tracker_data), tracker_response.status_code
    except requests.exceptions.RequestException as e:
        print(f"Error forwarding to tracker: {e}")
        return jsonify({"error": "Tracker request failed"}), 503
    except Exception as e:
        print(f"Error handling node request: {e}")
        return jsonify({"error": "Internal proxy error"}), 500

if __name__ == '__main__':
    app.run(host=TRACKER_IP, port=12367)
