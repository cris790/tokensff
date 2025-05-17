from flask import Flask, jsonify, request
from flask_caching import Cache
import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import binascii
import my_pb2
import output_pb2
import json
import warnings
from urllib3.exceptions import InsecureRequestWarning
from concurrent.futures import ThreadPoolExecutor, as_completed
import signal
import os
import sys
import resource
import logging
from logging.handlers import RotatingFileHandler

# Disable SSL warnings
warnings.filterwarnings("ignore", category=InsecureRequestWarning)

# Constants
AES_KEY = b'Yg&tc%DEuh6%Zc^8'
AES_IV = b'6oyZDr22E3ychjM%'
MAX_WORKERS = 30
MAX_TOKENS = 1000
CHUNK_SIZE = 50
CACHE_TIMEOUT = 25200  # 7 hours in seconds

# Initialize Flask app
app = Flask(__name__)

# Configure logging
log_handler = RotatingFileHandler('api.log', maxBytes=10*1024*1024, backupCount=5)
log_handler.setFormatter(logging.Formatter(
    '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
))
app.logger.addHandler(log_handler)
app.logger.setLevel(logging.INFO)

# Set memory limits (512MB)
soft, hard = resource.getrlimit(resource.RLIMIT_AS)
resource.setrlimit(resource.RLIMIT_AS, (512 * 1024 * 1024, hard))

# Cache configuration
cache_config = {
    'CACHE_TYPE': 'SimpleCache',
    'CACHE_DEFAULT_TIMEOUT': CACHE_TIMEOUT,
    'CACHE_THRESHOLD': 1000
}
cache = Cache(app, config=cache_config)

# Signal handlers for graceful shutdown
def handle_shutdown(signum, frame):
    app.logger.info("Shutdown signal received, exiting gracefully...")
    sys.exit(0)

signal.signal(signal.SIGINT, handle_shutdown)
signal.signal(signal.SIGTERM, handle_shutdown)

def get_token(password, uid):
    """Fetch token from Garena API"""
    url = "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant"
    headers = {
        "Host": "100067.connect.garena.com",
        "User-Agent": "GarenaMSDK/4.0.19P4(G011A ;Android 9;en;US;)",
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "close"
    }
    data = {
        "uid": uid,
        "password": password,
        "response_type": "token",
        "client_type": "2",
        "client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
        "client_id": "100067"
    }
    
    try:
        response = requests.post(url, headers=headers, data=data, timeout=10)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        app.logger.error(f"Token request failed for UID {uid}: {str(e)}")
        return None

def encrypt_message(key, iv, plaintext):
    """Encrypt data using AES-CBC"""
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_message = pad(plaintext, AES.block_size)
    return cipher.encrypt(padded_message)

def load_tokens(file_path, limit=600):
    """Load tokens from file with limit"""
    try:
        with open(file_path, 'r') as file:
            data = json.load(file)
            tokens = list(data.items())
            return tokens[:limit]
    except Exception as e:
        app.logger.error(f"Failed to load tokens: {str(e)}")
        return []

def parse_response(response_content):
    """Parse protobuf response"""
    response_dict = {}
    lines = response_content.split("\n")
    for line in lines:
        if ":" in line:
            key, value = line.split(":", 1)
            response_dict[key.strip()] = value.strip().strip('"')
    return response_dict

def process_token(uid, password):
    """Process a single token request"""
    token_data = get_token(password, uid)
    if not token_data:
        return {"uid": uid, "error": "Failed to get token"}

    # Create GameData protobuf
    game_data = my_pb2.GameData()
    game_data.timestamp = "2024-12-05 18:15:32"
    game_data.game_name = "free fire"
    game_data.game_version = 1
    game_data.version_code = "1.109.16"
    game_data.os_info = "Android OS 9 / API-28 (PI/rel.cjw.20220518.114133)"
    game_data.device_type = "Handheld"
    game_data.network_provider = "Verizon Wireless"
    game_data.connection_type = "WIFI"
    game_data.screen_width = 1280
    game_data.screen_height = 960
    game_data.dpi = "240"
    game_data.cpu_info = "ARMv7 VFPv3 NEON VMH | 2400 | 4"
    game_data.total_ram = 5951
    game_data.gpu_name = "Adreno (TM) 640"
    game_data.gpu_version = "OpenGL ES 3.0"
    game_data.user_id = "Google|74b585a9-0268-4ad3-8f36-ef41d2e53610"
    game_data.ip_address = "172.190.111.97"
    game_data.language = "en"
    game_data.open_id = token_data['open_id']
    game_data.access_token = token_data['access_token']
    game_data.platform_type = 4
    game_data.device_form_factor = "Handheld"
    game_data.device_model = "Asus ASUS_I005DA"
    game_data.field_60 = 32968
    game_data.field_61 = 29815
    game_data.field_62 = 2479
    game_data.field_63 = 914
    game_data.field_64 = 31213
    game_data.field_65 = 32968
    game_data.field_66 = 31213
    game_data.field_67 = 32968
    game_data.field_70 = 4
    game_data.field_73 = 2
    game_data.library_path = "/data/app/com.dts.freefireth-QPvBnTUhYWE-7DMZSOGdmA==/lib/arm"
    game_data.field_76 = 1
    game_data.apk_info = "5b892aaabd688e571f688053118a162b|/data/app/com.dts.freefireth-QPvBnTUhYWE-7DMZSOGdmA==/base.apk"
    game_data.field_78 = 6
    game_data.field_79 = 1
    game_data.os_architecture = "32"
    game_data.build_number = "2019117877"
    game_data.field_85 = 1
    game_data.graphics_backend = "OpenGLES2"
    game_data.max_texture_units = 16383
    game_data.rendering_api = 4
    game_data.encoded_field_89 = "\u0017T\u0011\u0017\u0002\b\u000eUMQ\bEZ\u0003@ZK;Z\u0002\u000eV\ri[QVi\u0003\ro\t\u0007e"
    game_data.field_92 = 9204
    game_data.marketplace = "3rd_party"
    game_data.encryption_key = "KqsHT2B4It60T/65PGR5PXwFxQkVjGNi+IMCK3CFBCBfrNpSUA1dZnjaT3HcYchlIFFL1ZJOg0cnulKCPGD3C3h1eFQ="
    game_data.total_storage = 111107
    game_data.field_97 = 1
    game_data.field_98 = 1
    game_data.field_99 = "4"
    game_data.field_100 = "4"

    # Serialize and encrypt
    serialized_data = game_data.SerializeToString()
    encrypted_data = encrypt_message(AES_KEY, AES_IV, serialized_data)
    hex_encrypted_data = binascii.hexlify(encrypted_data).decode('utf-8')

    # Send to server
    url = "https://loginbp.common.ggbluefox.com/MajorLogin"
    headers = {
        'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip",
        'Content-Type': "application/octet-stream",
        'Expect': "100-continue",
        'X-Unity-Version': "2018.4.11f1",
        'X-GA': "v1 1",
        'ReleaseVersion': "OB48"
    }
    edata = bytes.fromhex(hex_encrypted_data)

    try:
        response = requests.post(url, data=edata, headers=headers, verify=False, timeout=15)
        if response.status_code == 200:
            example_msg = output_pb2.Garena_420()
            try:
                example_msg.ParseFromString(response.content)
                response_dict = parse_response(str(example_msg))
                return {
                    "uid": uid,
                    "token": response_dict.get("token", "N/A")
                }
            except Exception as e:
                return {
                    "uid": uid,
                    "error": f"Failed to parse response: {str(e)}"
                }
        else:
            return {
                "uid": uid,
                "error": f"HTTP {response.status_code}: {response.reason}"
            }
    except requests.RequestException as e:
        return {
            "uid": uid,
            "error": f"Request failed: {str(e)}"
        }

def process_chunk(chunk):
    """Process a chunk of tokens"""
    results = []
    for uid, password in chunk:
        try:
            result = process_token(uid, password)
            results.append(result)
        except Exception as e:
            results.append({"uid": uid, "error": str(e)})
    return results

@app.route('/token', methods=['GET'])
@cache.cached(timeout=CACHE_TIMEOUT, query_string=True)
def get_responses():
    """Main endpoint to get tokens"""
    try:
        limit = min(request.args.get('limit', default=600, type=int), MAX_TOKENS)
        tokens = load_tokens("accs.txt", limit)
        
        if not tokens:
            return jsonify({"error": "No tokens available"}), 500

        responses = []
        successful = 0
        workers = min(MAX_WORKERS, len(tokens) // CHUNK_SIZE + 1)

        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = []
            
            # Process in chunks
            for i in range(0, len(tokens), CHUNK_SIZE):
                chunk = tokens[i:i + CHUNK_SIZE]
                futures.append(executor.submit(process_chunk, chunk))
            
            for future in as_completed(futures):
                try:
                    chunk_result = future.result()
                    responses.extend(chunk_result)
                    successful += sum(1 for r in chunk_result if 'token' in r)
                except Exception as e:
                    app.logger.error(f"Chunk processing failed: {str(e)}")

        return jsonify({
            "total": len(responses),
            "successful": successful,
            "failed": len(responses) - successful,
            "results": responses
        })
    except Exception as e:
        app.logger.error(f"Unexpected error in get_responses: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        "status": "healthy",
        "pid": os.getpid(),
        "memory": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    })

if __name__ == "__main__":
    # Production configuration
    port = int(os.environ.get('PORT', 50011))
    
    if os.environ.get('FLASK_ENV') == 'production':
        from waitress import serve
        serve(app, host="0.0.0.0", port=port, threads=50)
    else:
        # Development without auto-reload
        app.run(host="0.0.0.0", port=port, debug=False, use_reloader=False)
