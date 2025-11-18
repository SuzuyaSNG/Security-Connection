import base64
from flask import Flask, request, render_template, jsonify
from crypto import dh_serv

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/get_key', methods=['POST'])
def get_key():
    return jsonify({
        'P_serv': str(dh_serv.p),
        'server_public_key': str(dh_serv.public_key)
    })

@app.route('/dh_exchange', methods=['POST'])
def dh_exchange():
    client_public = int(request.json.get('client_public'))

    shared_secret = dh_serv.gen_secret(client_public)
    dh_serv.gen_key()

    if not shared_secret:
        return jsonify({'error': 'Key exchange failed'}), 400
    else:
        return jsonify({'shared_secret': str(shared_secret)})

@app.route('/sec_msg', methods=['POST'])
def secure_msg():
    try:
        
        if not request.json or 'encrypted_message' not in request.json:
            return jsonify({"error": "Missing encrypted_message"}), 400
            
        encrypted_msg_b64 = request.json.get('encrypted_message')
        hmac_msg = request.json.get('hmac')
        
        
        encrypted_msg = base64.b64decode(encrypted_msg_b64)

        if not dh_serv.verify_hmac(encrypted_msg, hmac_msg):
            expected_hmac = dh_serv.create_hmac(encrypted_msg)
            return jsonify({"error": "HMAC verification failed"}), 400

        
        decrypted_msg = dh_serv.decrypt_msg(encrypted_msg)
        
        response_data = f"Server received: {decrypted_msg.decode('utf-8')}"
        print(f"Response data: {response_data}")
        
        encrypt_response = dh_serv.encrypt_msg(response_data)
        response_hmac = dh_serv.create_hmac(encrypt_response)
        
        return jsonify({
            'encrypted_response': base64.b64encode(encrypt_response).decode('utf-8'),
            'hmac': response_hmac
        })
        
    except Exception as e:
        print(f"Error in secure_msg: {str(e)}")
        import traceback
        traceback.print_exc()  
        return jsonify({"error": f"Server error: {str(e)}"}), 500

if __name__ == '__main__':
    # Временное использование adhoc, в версии 2 будет замененно на свой сертификат 
    app.run(host='address', port=443, ssl_context='adhoc')
