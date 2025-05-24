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
import socket
import socks
from fake_useragent import UserAgent

# Ignorar avisos de certificado SSL
warnings.filterwarnings("ignore", category=InsecureRequestWarning)

# Configurações
AES_KEY = b'Yg&tc%DEuh6%Zc^8'
AES_IV = b'6oyZDr22E3ychjM%'
MAX_WORKERS = 50  # Aumentado de 15 para 50
REQUEST_DELAY = (0.1, 0.5)  # Intervalo aleatório entre requisições
PROXY_LIST = []  # Preencher com seus proxies se necessário

# Inicializar colorama
init(autoreset=True)

# Inicializar o aplicativo Flask
app = Flask(__name__)

# Configurar o cache com duração de 7 horas
cache = Cache(app, config={'CACHE_TYPE': 'SimpleCache', 'CACHE_DEFAULT_TIMEOUT': 25200})

# Inicializar UserAgent para headers aleatórios
ua = UserAgent()

def get_working_proxy():
    """Retorna um proxy funcional da lista"""
    if not PROXY_LIST:
        return None
    
    for proxy in random.sample(PROXY_LIST, len(PROXY_LIST)):
        try:
            ip, port = proxy.split(':')
            socks.set_default_proxy(socks.SOCKS5, ip, int(port))
            socket.socket = socks.socksocket
            # Testar o proxy
            test_ip = requests.get('https://api.ipify.org', timeout=5).text
            print(f"Proxy funcionando: {proxy} (IP: {test_ip})")
            return proxy
        except:
            continue
    return None

def get_token(password, uid, attempt=1, max_attempts=3):
    """Obtém token com retry automático"""
    url = "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant"
    
    headers = {
        "Host": "100067.connect.garena.com",
        "User-Agent": ua.random,
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
        proxy = get_working_proxy()
        proxies = {
            'http': f'socks5://{proxy}',
            'https': f'socks5://{proxy}'
        } if proxy else None
        
        response = requests.post(
            url, 
            headers=headers, 
            data=data, 
            proxies=proxies,
            timeout=10,
            verify=False
        )
        
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 429 and attempt < max_attempts:
            # Rate limit atingido - esperar e tentar novamente
            wait_time = random.uniform(1, 5)
            print(f"Rate limit atingido para {uid}. Tentativa {attempt}/{max_attempts}. Esperando {wait_time:.2f}s...")
            time.sleep(wait_time)
            return get_token(password, uid, attempt+1, max_attempts)
        else:
            print(f"Falha ao obter token para {uid}. Status: {response.status_code}")
            return None
    except Exception as e:
        print(f"Erro ao obter token para {uid}: {str(e)}")
        if attempt < max_attempts:
            return get_token(password, uid, attempt+1, max_attempts)
        return None

def encrypt_message(key, iv, plaintext):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_message = pad(plaintext, AES.block_size)
    encrypted_message = cipher.encrypt(padded_message)
    return encrypted_message

def load_tokens(file_path, limit=500):
    with open(file_path, 'r') as file:
        data = json.load(file)
        tokens = list(data.items())
        if limit is not None:
            tokens = tokens[:limit]
        return tokens

def parse_response(response_content):
    response_dict = {}
    lines = response_content.split("\n")
    for line in lines:
        if ":" in line:
            key, value = line.split(":", 1)
            response_dict[key.strip()] = value.strip().strip('"')
    return response_dict

def process_token(uid, password):
    """Processa um token com melhor tratamento de erros e headers aleatórios"""
    # Delay aleatório entre requisições
    time.sleep(random.uniform(*REQUEST_DELAY))
    
    token_data = get_token(password, uid)
    if not token_data:
        return {"uid": uid, "error": "Falha ao obter o token"}

    # Criar o objeto GameData Protobuf
    game_data = my_pb2.GameData()
    # ... (seu código existente de preenchimento do game_data)
    
    # Serializar os dados
    serialized_data = game_data.SerializeToString()

    # Criptografar os dados
    encrypted_data = encrypt_message(AES_KEY, AES_IV, serialized_data)
    hex_encrypted_data = binascii.hexlify(encrypted_data).decode('utf-8')

    # Headers aleatórios
    headers = {
        'User-Agent': ua.random,
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
        proxy = get_working_proxy()
        proxies = {
            'http': f'socks5://{proxy}',
            'https': f'socks5://{proxy}'
        } if proxy else None
        
        response = requests.post(
            "https://loginbp.common.ggbluefox.com/MajorLogin",
            data=edata,
            headers=headers,
            proxies=proxies,
            timeout=10,
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
                    "error": f"Falha ao desserializar: {e}",
                    "status": "error"
                }
        else:
            return {
                "uid": uid,
                "error": f"HTTP {response.status_code}",
                "status": "error"
            }
    except requests.RequestException as e:
        return {
            "uid": uid,
            "error": f"Request failed: {e}",
            "status": "error"
        }

@app.route('/token', methods=['GET'])
@cache.cached(timeout=25200, query_string=True)
def get_responses():
    """Endpoint principal com suporte a parâmetros de controle"""
    limit = request.args.get('limit', default=500, type=int)
    workers = min(request.args.get('workers', default=MAX_WORKERS, type=int), 100)
    
    tokens = load_tokens("accs.txt", limit)
    responses = []
    
    print(f"Iniciando processamento de {len(tokens)} tokens com {workers} workers...")
    
    with ThreadPoolExecutor(max_workers=workers) as executor:
        future_to_uid = {
            executor.submit(process_token, uid, password): uid 
            for uid, password in tokens
        }
        
        for future in as_completed(future_to_uid):
            try:
                response = future.result()
                responses.append(response)
                if response.get('status') == 'success':
                    print(f"{Fore.GREEN}Sucesso: {response['uid']}")
                else:
                    print(f"{Fore.YELLOW}Erro: {response['uid']} - {response.get('error', 'Unknown error')}")
            except Exception as e:
                uid = future_to_uid[future]
                responses.append({"uid": uid, "error": str(e), "status": "error"})
                print(f"{Fore.RED}Falha crítica: {uid} - {str(e)}")
    
    stats = {
        'total': len(responses),
        'success': sum(1 for r in responses if r.get('status') == 'success'),
        'errors': sum(1 for r in responses if r.get('status') != 'success')
    }
    
    print(f"\nEstatísticas: {Fore.CYAN}{stats}")
    return jsonify({
        'data': responses,
        'stats': stats
    })

if __name__ == "__main__":
    # Carregar proxies de um arquivo se existir
    try:
        with open('proxies.txt', 'r') as f:
            PROXY_LIST = [line.strip() for line in f if line.strip()]
        print(f"Carregados {len(PROXY_LIST)} proxies")
    except FileNotFoundError:
        print("Arquivo proxies.txt não encontrado. Continuando sem proxies")
    
    app.run(host="0.0.0.0", port=50011, threaded=True)
