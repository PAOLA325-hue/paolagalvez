from flask import Flask, request, jsonify
import requests
import base64

app = Flask(__name__)
api_key = '94af56fb3d7ed2b77eb04e529a6576bcd8c01ca6b04addc796ef82317082a557'  # Reemplaza con tu clave de API de VirusTotal

@app.route('/analizar', methods=['POST'])
def analizar():
    data = request.get_json()
    url = data['url']
    url_encoded = base64.b64encode(url.encode()).decode()

    headers = {
        'x-apikey': api_key,
        'Content-Type': 'application/json'
    }
    response = requests.get(f'https://www.virustotal.com/api/v3/urls/{url_encoded}', headers=headers)

    if response.status_code != 200:
        return jsonify({'error': 'Error al conectar con VirusTotal'}), 500

    return jsonify(response.json())

if __name__ == '__main__':
    app.run(port=5000)