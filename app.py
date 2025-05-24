from flask import Flask, jsonify, request
from flask_caching import Cache
import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import binascii
import my_pb2
import output_pb2
import json
from colorama import Fore, Style, init
import warnings
from urllib3.exceptions import InsecureRequestWarning
from concurrent.futures import ThreadPoolExecutor, as_completed
import random
import time
import threading

# Ignore SSL warnings
warnings.filterwarnings("ignore", category=InsecureRequestWarning)

# Configuration
AES_KEY = b'Yg&tc%DEuh6%Zc^8'
AES_IV = b'6oyZDr22E3ychjM%'
MAX_WORKERS = 30
MIN_DELAY = 0.5  # Minimum delay between requests in seconds
MAX_DELAY = 2.0  # Maximum delay between requests in seconds
MAX_RETRIES = 3   # Max retry attempts for failed requests

# Initialize colorama
init(autoreset=True)

# Initialize Flask app
app = Flask(__name__)

# Configure cache
cache = Cache(app, config={'CACHE_TYPE': 'SimpleCache', 'CACHE_DEFAULT_TIMEOUT': 25200})

# Global variables
user_agents = []
delayer_lock = threading.Lock()
last_request_time = 0

def load_user_agents(file_path):
    """Load user agents from file"""
    try:
        with open(file_path, 'r') as file:
            return [line.strip() for line in file if line.strip()]
    except FileNotFoundError:
        print(f"{Fore.RED}User agents file not found, using default")
        return [
            "GarenaMSDK/4.0.19P4(G011A ;Android 9;en;US;)",
            "Dalvik/2.1.0 (Linux; U; Android 10; SM-G975F Build/QP1A.190711.020)",
            "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)"
        ]

def apply_request_delay():
    """Apply random delay between requests"""
    global last_request_time
    with delayer_lock:
        elapsed = time.time() - last_request_time
        wait_time = max(0, random.uniform(MIN_DELAY, MAX_DELAY) - elapsed
        if wait_time > 0:
            time.sleep(wait_time)
        last_request_time = time.time()

def get_token(password, uid, attempt=1):
    """Get authentication token with retry logic"""
    url = "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant"
    
    headers = {
        "Host": "100067.connect.garena.com",
        "User-Agent": random.choice(user_agents),
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
        apply_request_delay()
        response = requests.post(url, headers=headers, data=data, timeout=10, verify=False)
        
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 429 and attempt < MAX_RETRIES:
            wait_time = random.uniform(1, 5)
            print(f"{Fore.YELLOW}Rate limit hit for {uid}. Attempt {attempt}/{MAX_RETRIES}. Waiting {wait_time:.2f}s...")
            time.sleep(wait_time)
            return get_token(password, uid, attempt+1)
        else:
            print(f"{Fore.RED}Failed to get token for {uid}. Status: {response.status_code}")
            return None
    except Exception as e:
        print(f"{Fore.RED}Error getting token for {uid}: {str(e)}")
        if attempt < MAX_RETRIES:
            return get_token(password, uid, attempt+1)
        return None

def encrypt_message(key, iv, plaintext):
    """Encrypt message using AES-CBC"""
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_message = pad(plaintext, AES.block_size)
    return cipher.encrypt(padded_message)

def load_tokens(file_path, limit=None):
    """Load tokens from JSON file"""
    with open(file_path, 'r') as file:
        data = json.load(file)
        tokens = list(data.items())
        if limit is not None:
            tokens = tokens[:limit]
        return tokens

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
    """Process a single token with enhanced features"""
    token_data = get_token(password, uid)
    if not token_data:
        return {"uid": uid, "error": "Failed to get token", "status": "error"}
    
    # Prepare GameData protobuf
    game_data = my_pb2.GameData()
    # ... (your existing GameData population code)
    
    # Serialize and encrypt
    serialized_data = game_data.SerializeToString()
    encrypted_data = encrypt_message(AES_KEY, AES_IV, serialized_data)
    hex_encrypted_data = binascii.hexlify(encrypted_data).decode('utf-8')
    
    # Prepare request with random User-Agent
    headers = {
        'User-Agent': random.choice(user_agents),
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip",
        'Content-Type': "application/octet-stream",
        'Expect': "100-continue",
        'X-Unity-Version': "2018.4.11f1",
        'X-GA': "v1 1",
        'ReleaseVersion': "OB48"
    }
    
    try:
        apply_request_delay()
        response = requests.post(
            "https://loginbp.common.ggbluefox.com/MajorLogin",
            data=bytes.fromhex(hex_encrypted_data),
            headers=headers,
            timeout=15,
            verify=False
        )
        
        if response.status_code == 200:
            example_msg = output_pb2.Garena_420()
            try:
                example_msg.ParseFromString(response.content)
                response_dict = parse_response(str(example_msg))
                return {
                    "uid": uid,
                    "token": response_dict.get("token", "N/A"),
                    "status": "success"
                }
            except Exception as e:
                return {
                    "uid": uid,
                    "error": f"Parse error: {e}",
                    "status": "error"
                }
        else:
            return {
                "uid": uid,
                "error": f"HTTP {response.status_code}",
                "status": "error"
            }
    except Exception as e:
        return {
            "uid": uid,
            "error": f"Request failed: {e}",
            "status": "error"
        }

@app.route('/token', methods=['GET'])
@cache.cached(timeout=25200, query_string=True)
def get_responses():
    """Main endpoint with enhanced controls"""
    # Get parameters
    limit = request.args.get('limit', default=500, type=int)
    workers = min(request.args.get('workers', default=MAX_WORKERS, type=int), 50)
    min_delay = request.args.get('min_delay', default=MIN_DELAY, type=float)
    max_delay = request.args.get('max_delay', default=MAX_DELAY, type=float)
    
    # Update delay settings
    global MIN_DELAY, MAX_DELAY
    MIN_DELAY, MAX_DELAY = min_delay, max_delay
    
    tokens = load_tokens("accs.txt", limit)
    responses = []
    
    print(f"{Fore.GREEN}Starting processing of {len(tokens)} tokens with:")
    print(f"- Workers: {workers}")
    print(f"- Delay: {min_delay}-{max_delay}s")
    print(f"- User Agents: {len(user_agents)} loaded")
    
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(process_token, uid, password): uid 
            for uid, password in tokens
        }
        
        for future in as_completed(futures):
            try:
                result = future.result()
                responses.append(result)
                
                if result.get('status') == 'success':
                    print(f"{Fore.GREEN}✓ {result['uid']}")
                else:
                    print(f"{Fore.YELLOW}✗ {result['uid']}: {result.get('error', 'Unknown error')}")
            except Exception as e:
                uid = futures[future]
                responses.append({"uid": uid, "error": str(e), "status": "error"})
                print(f"{Fore.RED}✗ {uid}: CRITICAL - {str(e)}")
    
    # Generate statistics
    success = sum(1 for r in responses if r.get('status') == 'success')
    errors = len(responses) - success
    
    print(f"\n{Fore.CYAN}=== Results ===")
    print(f"Total: {len(responses)}")
    print(f"Success: {success}")
    print(f"Errors: {errors}")
    print(f"Success rate: {success/len(responses)*100:.2f}%")
    
    return jsonify({
        "data": responses,
        "stats": {
            "total": len(responses),
            "success": success,
            "errors": errors,
            "success_rate": f"{success/len(responses)*100:.2f}%"
        }
    })

if __name__ == "__main__":
    # Load user agents
    user_agents = load_user_agents("useragents.txt")
    
    # Load configuration if available
    try:
        with open('config.json', 'r') as f:
            config = json.load(f)
            MIN_DELAY = config.get('min_delay', 0.5)
            MAX_DELAY = config.get('max_delay', 2.0)
            MAX_WORKERS = config.get('max_workers', 30)
    except FileNotFoundError:
        print(f"{Fore.YELLOW}No config.json found. Using default settings")
    
    app.run(host="0.0.0.0", port=50011, threaded=True)
