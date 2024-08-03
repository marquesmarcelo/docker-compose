from flask import Flask
import socket

app = Flask(__name__)

@app.route('/')
def home():
    container_id = socket.gethostname()
    return f"Container ID: {container_id}"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80)
