from flask import Flask, request, jsonify
import asyncio
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from google.protobuf.json_format import MessageToJson
import binascii
import aiohttp
import requests
import json
import like_pb2
import like_count_pb2
import uid_generator_pb2
from google.protobuf.message import DecodeError
import urllib3

# Suppress InsecureRequestWarning from verify=False
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)

def load_tokens(server_name):
    try:
        if server_name == "BD":
            with open("token_bd.json", "r") as f:
                tokens = json.load(f)
        elif server_name in {"BR", "US", "SAC", "NA"}:
            with open("token_br.json", "r") as f:
                tokens = json.load(f)
        else:
            # Default to BD tokens if server_name is unknown
            with open("token_bd.json", "r") as f:
                tokens = json.load(f)
        return tokens
    except FileNotFoundError:
        app.logger.error(f"Token file not found for server {server_name}")
        return None
    except Exception as e:
        app.logger.error(f"Error loading tokens for server {server_name}: {e}")
        return None

def encrypt_message(plaintext):
    try:
        key = b'Yg&tc%DEuh6%Zc^8'
        iv = b'6oyZDr22E3ychjM%'
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded_message = pad(plaintext, AES.block_size)
        encrypted_message = cipher.encrypt(padded_message)
        return binascii.hexlify(encrypted_message).decode('utf-8')
    except Exception as e:
        app.logger.error(f"Error encrypting message: {e}")
        return None

def create_protobuf_message(user_id, region):
    try:
        message = like_pb2.like()
        message.uid = int(user_id)
        message.region = region
        return message.SerializeToString()
    except Exception as e:
        app.logger.error(f"Error creating protobuf message: {e}")
        return None

async def send_request(encrypted_uid, token, url):
    try:
        edata = bytes.fromhex(encrypted_uid)
        headers = {
            'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip",
            'Authorization': f"Bearer {token}",
            'Content-Type': "application/x-www-form-urlencoded",
            'Expect': "100-continue",
            'X-Unity-Version': "2018.4.11f1",
            'X-GA': "v1 1",
            'ReleaseVersion': "OB50"
        }
        # Set a timeout for the async request
        timeout = aiohttp.ClientTimeout(total=10)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.post(url, data=edata, headers=headers) as response:
                if response.status != 200:
                    app.logger.error(f"Like request failed with status code: {response.status}")
                    return response.status
                return await response.text()
    except asyncio.TimeoutError:
        app.logger.error("Like request timed out.")
        return "Timeout"
    except Exception as e:
        app.logger.error(f"Exception in send_request: {e}")
        return None

async def send_multiple_requests(uid, server_name, url):
    try:
        region = server_name
        protobuf_message = create_protobuf_message(uid, region)
        if protobuf_message is None:
            app.logger.error("Failed to create protobuf message.")
            return None
        encrypted_uid = encrypt_message(protobuf_message)
        if encrypted_uid is None:
            app.logger.error("Encryption failed.")
            return None
        tasks = []
        tokens = load_tokens(server_name)
        if tokens is None:
            app.logger.error("Failed to load tokens.")
            return None
        for i in range(120):
            token = tokens[i % len(tokens)]["token"]
            tasks.append(send_request(encrypted_uid, token, url))
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return results
    except Exception as e:
        app.logger.error(f"Exception in send_multiple_requests: {e}")
        return None

def create_protobuf(uid):
    try:
        message = uid_generator_pb2.uid_generator()
        message.saturn_ = int(uid)
        message.garena = 1
        return message.SerializeToString()
    except Exception as e:
        app.logger.error(f"Error creating uid protobuf: {e}")
        return None

def enc(uid):
    protobuf_data = create_protobuf(uid)
    if protobuf_data is None:
        return None
    encrypted_uid = encrypt_message(protobuf_data)
    return encrypted_uid

def make_request(encrypt, server_name, token):
    try:
        if server_name == "BD":
            url = "https://client.bd.freefiremobile.com/GetPlayerPersonalShow"
        elif server_name in {"BR", "US", "SAC", "NA"}:
            url = "https://client.us.freefiremobile.com/GetPlayerPersonalShow"
        else:
            url = "https://clientbp.ggblueshark.com/GetPlayerPersonalShow"
            
        app.logger.info(f"Making request to: {url} for server: {server_name}")
            
        edata = bytes.fromhex(encrypt)
        headers = {
            'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip",
            'Authorization': f"Bearer {token}",
            'Content-Type': "application/x-www-form-urlencoded",
            'Expect': "100-continue",
            'X-Unity-Version': "2018.4.11f1",
            'X-GA': "v1 1",
            'ReleaseVersion': "OB50"
        }
        
        # Add timeout to requests.post
        response = requests.post(url, data=edata, headers=headers, verify=False, timeout=10)

        # --- START OF IMPROVED ERROR HANDLING ---

        # Check for non-200 status code
        if response.status_code != 200:
            app.logger.error(f"API Error: Status Code {response.status_code}")
            try:
                # Try to log the response as text, it might be an error message
                app.logger.error(f"API Error Response Body: {response.text}")
            except Exception:
                app.logger.error("API Error Response Body could not be read as text.")
            return None # This will trigger your "Failed to retrieve" exception

        # Simplify content processing. response.content is already bytes.
        binary = response.content
        
        if not binary:
            app.logger.error("API Error: Received empty response content.")
            return None

        app.logger.info(f"Received {len(binary)} bytes from API. Attempting to decode protobuf.")

        # decode_protobuf already has its own try/except and logging
        decode = decode_protobuf(binary) 
        
        if decode is None:
            app.logger.error("Protobuf decoding returned None. The response may not be a valid protobuf.")
            # Log the raw binary (or part of it) to help debug
            app.logger.error(f"Raw binary (first 50 bytes): {binary[:50].hex()}")
            return None
            
        app.logger.info("Protobuf decoded successfully.")
        return decode
        
    except requests.exceptions.RequestException as e:
        # Catch specific requests-related errors (like timeout, connection error)
        app.logger.error(f"Error in make_request (requests exception): {e}")
        return None
    except binascii.Error as e:
        # Catch errors from bytes.fromhex(encrypt)
        app.logger.error(f"Error in make_request (binascii error, likely bad 'encrypt' param): {e}")
        return None
    except Exception as e:
        # Catch any other unexpected errors
        app.logger.error(f"Unexpected error in make_request: {e}")
        return None

def decode_protobuf(binary):
    try:
        items = like_count_pb2.Info()
        items.ParseFromString(binary)
        return items
    except DecodeError as e:
        app.logger.error(f"Error decoding Protobuf data: {e}")
        return None
    except Exception as e:
        app.logger.error(f"Unexpected error during protobuf decoding: {e}")
        return None

def fetch_player_info(uid):
    try:
        url = f"https://nr-codex-info.vercel.app/get?uid={uid}"
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            data = response.json()
            account_info = data.get("AccountInfo", {})
            return {
                "Level": account_info.get("AccountLevel", "NA"),
                "Region": account_info.get("AccountRegion", "NA"),
                "ReleaseVersion": account_info.get("ReleaseVersion", "NA")
            }
        else:
            app.logger.error(f"Player info API failed with status code: {response.status_code}")
            return {"Level": "NA", "Region": "NA", "ReleaseVersion": "NA"}
    except requests.exceptions.RequestException as e:
        app.logger.error(f"Error fetching player info from API: {e}")
        return {"Level": "NA", "Region": "NA", "ReleaseVersion": "NA"}

@app.route('/like', methods=['GET'])
def handle_requests():
    uid = request.args.get("uid")
    server_name = request.args.get("server_name", "").upper()
    if not uid or not server_name:
        return jsonify({"error": "UID and server_name are required"}), 400

    try:
        # Renamed inner function to avoid confusion
        def _process_like_request():
            # Fetch player info from the new API
            player_info = fetch_player_info(uid)
            region = player_info["Region"]
            level = player_info["Level"]
            release_version = player_info["ReleaseVersion"]

            # Validate server_name against region from API
            if region != "NA" and server_name != region:
                app.logger.warning(f"Server name {server_name} does not match API region {region}. Using API region.")
                server_name_used = region
            else:
                server_name_used = server_name

            tokens = load_tokens(server_name_used)
            if tokens is None:
                raise Exception("Failed to load tokens.")
            token = tokens[0]['token']
            encrypted_uid = enc(uid)
            if encrypted_uid is None:
                raise Exception("Encryption of UID failed.")

            before = make_request(encrypted_uid, server_name_used, token)
            if before is None:
                # This is the line from your screenshot
                raise Exception("Failed to retrieve initial player info.")
            try:
                jsone = MessageToJson(before)
            except Exception as e:
                raise Exception(f"Error converting 'before' protobuf to JSON: {e}")
            
            data_before = json.loads(jsone)
            before_like = data_before.get('AccountInfo', {}).get('Likes', 0)
            try:
                before_like = int(before_like)
            except Exception:
                before_like = 0
            app.logger.info(f"Likes before command: {before_like}")

            if server_name_used == "BD":
                url = "https://client.bd.freefiremobile.com/LikeProfile"
            elif server_name_used in {"BR", "US", "SAC", "NA"}:
                url = "https://client.us.freefiremobile.com/LikeProfile"
            else:
                url = "https://clientbp.ggblueshark.com/LikeProfile"

            asyncio.run(send_multiple_requests(uid, server_name_used, url))

            after = make_request(encrypted_uid, server_name_used, token)
            if after is None:
                raise Exception("Failed to retrieve player info after like requests.")
            try:
                jsone_after = MessageToJson(after)
            except Exception as e:
                raise Exception(f"Error converting 'after' protobuf to JSON: {e}")
            
            data_after = json.loads(jsone_after)
            after_like = int(data_after.get('AccountInfo', {}).get('Likes', 0))
            player_uid = int(data_after.get('AccountInfo', {}).get('UID', 0))
            player_name = str(data_after.get('AccountInfo', {}).get('PlayerNickname', ''))
            like_given = after_like - before_like
            status = 1 if like_given > 0 else 2 # More accurate status
            result = {
                "LikesGivenRAJAN": like_given,
                "LikesafterCommand": after_like,
                "LikesbeforeCommand": before_like,
                "PlayerNickname": player_name,
                "Region": region,
                "Level": level,
                "UID": player_uid,
                "ReleaseVersion": release_version,
                "status": status
            }
            return result

        result = _process_like_request()
        return jsonify(result)
    except Exception as e:
        app.logger.error(f"Error processing request: {e}")
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    # Set debug=False for production, True for development
    # use_reloader=True is generally good for development
    app.run(debug=True, use_reloader=True)
