from flask import Flask, request, jsonify
import os
import amaas.grpc
import time
import json

from dotenv import load_dotenv
load_dotenv()

UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def malware_scan(file):
    handle = amaas.grpc.init_by_region(region=os.getenv("V1_REGION"), api_key=os.getenv("V1_API_KEY"))
    try:
        result = amaas.grpc.scan_file(handle, file_name=file, tags='SDK', pml=True, feedback=True)
        amaas.grpc.quit(handle)
        print(result)
        if json.loads(result)["scanResult"] == 1:
            return False, json.loads(result)["foundMalwares"]
        return True, json.loads(result)["foundMalwares"]
    except Exception as e:
        print(e)


@app.route('/upload', methods=['POST'])
def upload_file():
    print("Upload")
    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400

    files = request.files.getlist('file')
    saved_files = []

    for file in files:
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        file.save(filepath)
        saved_files.append(file.filename)
        scanResult, scanMessage = malware_scan(filepath)
        if scanResult:
            return jsonify({"message": "clean", "scanResult": f"{scanMessage}"}), 200
        else:
            return jsonify({"message": "Malware", "scanResult": f"{scanMessage}"}), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8443)
