# -*- coding: utf-8 -*-
import os
import sqlite3
import hmac
import hashlib
from Cryptodome.Cipher import AES

# 配置参数 (DB_DIR是数据库目录，TEMP_DIR是存放数据库的目录wechat_temp目录不存在自动创建请勿放在同一目录下) 
DB_DIR = r"C:\export\weiixn\endb"
DB_KEY = "这里是key"
TEMP_DIR = r"C:\export\weiixn\wechat_temp"
SQLITE_FILE_HEADER = b"SQLite format 3\x00"
KEY_SIZE = 32
DEFAULT_PAGESIZE = 4096


def decrypt(key, db_path, out_path):
    """
    解密微信数据库
    :param key: 64位16进制密钥
    :param db_path: 加密数据库路径
    :param out_path: 解密输出路径
    :return: (bool, result)
    """
    if not os.path.exists(db_path) or not os.path.isfile(db_path):
        return False, f"文件不存在: {db_path}"
    if len(key) != 64:
        return False, "无效的密钥长度"

    password = bytes.fromhex(key.strip())

    try:
        with open(db_path, "rb") as f:
            blist = f.read()
    except Exception as e:
        return False, f"读取失败: {e}"

    salt = blist[:16]
    first = blist[16:4096]
    if len(salt) != 16:
        return False, "无效的数据库格式"

    # 生成密钥
    mac_salt = bytes([(salt[i] ^ 58) for i in range(16)])
    byteHmac = hashlib.pbkdf2_hmac("sha1", password, salt, 64000, KEY_SIZE)
    mac_key = hashlib.pbkdf2_hmac("sha1", byteHmac, mac_salt, 2, KEY_SIZE)

    # 验证HMAC
    hash_mac = hmac.new(mac_key, blist[16:4064], hashlib.sha1)
    hash_mac.update(b'\x01\x00\x00\x00')
    if hash_mac.digest() != first[-32:-12]:
        return False, "密钥验证失败"

    # 解密数据
    try:
        with open(out_path, "wb") as deFile:
            deFile.write(SQLITE_FILE_HEADER)
            for i in range(0, len(blist), 4096):
                chunk = blist[i:i + 4096] if i > 0 else blist[16:i + 4096]
                iv = chunk[-48:-32]
                cipher = AES.new(byteHmac, AES.MODE_CBC, iv)
                decrypted = cipher.decrypt(chunk[:-48])
                deFile.write(decrypted)
                deFile.write(chunk[-48:])
        return True, "解密成功"
    except Exception as e:
        return False, f"解密失败: {e}"


def main():
    # 检查存放目录和解密目录是否在同一目录
    if os.path.abspath(DB_DIR) == os.path.abspath(TEMP_DIR):
        print("请修改存放目录，存放目录和解密目录不能相同。")
        return

    # 创建临时目录
    if not os.path.exists(TEMP_DIR):
        os.makedirs(TEMP_DIR)

    # 遍历指定文件夹及其子目录下的所有文件
    for root, dirs, files in os.walk(DB_DIR):
        for file in files:
            db_path = os.path.join(root, file)
            # 解密后文件的输出路径
            out_path = os.path.join(TEMP_DIR, file)

            # 步骤1：解密数据库
            print(f"[1/5] 正在解密数据库: {db_path}...")
            success, msg = decrypt(DB_KEY, db_path, out_path)
            if success:
                print(f"[+] 解密成功: {out_path}")
            else:
                print(f"[-] 解密失败: {msg}")
                if os.path.exists(out_path):
                    os.remove(out_path)

    print(f"解密后的文件存储在: {TEMP_DIR}")


if __name__ == "__main__":
    main()
    