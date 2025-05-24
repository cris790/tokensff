from flask import Flask, jsonify, request
from flask_caching import Cache
import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import binascii
import my_pb2
import output_pb2
import json
from colorama import Fore, init
import warnings
from urllib3.exceptions import InsecureRequestWarning
from concurrent.futures import ThreadPoolExecutor, as_completed
import random

# Ignorar avisos SSL
warnings.filterwarnings("ignore", category=InsecureRequestWarning)

AES_KEY = b'Yg&tc%DEuh6%Zc^8'
AES_IV = b'6oyZDr22E3ychjM%'

# Inicializar colorama
init(autoreset=True)

# Flask App
app = Flask(__name__)

# Cache por 7 horas
cache = Cache(app, config={'CACHE_TYPE': 'SimpleCache', 'CACHE_DEFAULT_TIMEOUT': 25200})

# Carregar User-Agents
def load_user_agents(file_path="useragents.txt"):
    try:
        with open(file_path, "r") as file:
            return [line.strip() for line in file if line.strip()]
    except FileNotFoundError:
        print(Fore.RED + "Arquivo useragents.txt não encontrado!")
        return ["Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)"]  # fallback padrão

user_agents_list = load_user_agents()

# Função para pegar token
def get_token(password, uid):
    url = "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant"
    headers = {
        "Host": "100067.connect.garena.com",
        "User-Agent": random.choice(user_agents_list),
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
    response = requests.post(url, headers=headers, data=data)
    if response.status_code != 200:
        return None
    return response.json()

# Criptografia AES
def encrypt_message(key, iv, plaintext):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_message = pad(plaintext, AES.block_size)
    encrypted_message = cipher.encrypt(padded_message)
    return encrypted_message

# Ler tokens do arquivo
def load_tokens(file_path, limit=100):
    with open(file_path, 'r') as file:
        data = json.load(file)
        tokens = list(data.items())
        if limit is not None:
            tokens = tokens[:limit]
        return tokens

# Parser de resposta
def parse_response(response_content):
    response_dict = {}
    lines = response_content.split("\n")
    for line in lines:
        if ":" in line:
            key, value = line.split(":", 1)
            response_dict[key.strip()] = value.strip().strip('"')
    return response_dict

# Processar token individual
def process_token(uid, password):
    token_data = get_token(password, uid)
    if not token_data:
        return {"uid": uid, "error": "Falha ao obter o token"}

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

    serialized_data = game_data.SerializeToString()
    encrypted_data = encrypt_message(AES_KEY, AES_IV, serialized_data)
    hex_encrypted_data = binascii.hexlify(encrypted_data).decode('utf-8')

    url = "https://loginbp.common.ggbluefox.com/MajorLogin"
    headers = {
        'User-Agent': random.choice(user_agents_list),
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
        response = requests.post(url, data=edata, headers=headers, verify=False)
        if response.status_code == 200:
            example_msg = output_pb2.Garena_420()
            try:
                example_msg.ParseFromString(response.content)
                response_dict = parse_response(str(example_msg))
                return {
                    "token": response_dict.get("token", "N/A")
                }
            except Exception as e:
                return {
                    "uid": uid,
                    "error": f"Falha ao desserializar: {e}"
                }
        else:
            return {
                "uid": uid,
                "error": f"Erro HTTP {response.status_code}: {response.reason}"
            }
    except requests.RequestException as e:
        return {
            "uid": uid,
            "error": f"Erro na requisição: {e}"
        }

# Endpoint da API
@app.route('/token', methods=['GET'])
@cache.cached(timeout=25200)
def get_responses():
    limit = request.args.get('limit', default=500, type=int)
    tokens = load_tokens("accs.txt", limit)
    responses = []

    with ThreadPoolExecutor(max_workers=15) as executor:
        future_to_uid = {executor.submit(process_token, uid, password): uid for uid, password in tokens}
        for future in as_completed(future_to_uid):
            try:
                response = future.result()
                responses.append(response)
            except Exception as e:
                responses.append({"uid": future_to_uid[future], "error": str(e)})

    return jsonify(responses)

# Iniciar o app
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=50011)
