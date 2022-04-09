from multiprocessing import pool
from pprint import pp
import sqlite3
import hashlib
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP


NAME_BASE = "system.db"
point_block = 0
code = "nooneknows"

def TranslateBlockInfo(bdata):
    tdata = bdata.split(", ")
    blockinfo = []
    for i in range(0, len(tdata)):
        blockinfo.append(tdata[i].split(": "))

    iblock = {}
    for i in range(0, len(blockinfo)):
        iblock[blockinfo[i][0]] = blockinfo[i][1]
    return iblock

def DecryptBlock():
    global point_block
    global code
    name = "block_" + str(point_block-1) + ".bin"
    with open(name, "rb") as fobj:
        private_key = RSA.import_key(
            open("private_key.bin").read(),
            passphrase=code
        )
        enc_session_key, nonce, tag, ciphertext = [
            fobj.read(x) for x in (private_key.size_in_bytes(), 16, 16, -1)
        ]
        cipher_rsa = PKCS1_OAEP.new(private_key)
        session_key = cipher_rsa.decrypt(enc_session_key)
        cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
        data = cipher_aes.decrypt_and_verify(ciphertext, tag)
        data = data.decode("utf-8")
        data = str(data)
    return data

def AddBlock(crsa, ctext, tag, caes):
    global point_block
    name = "block_" + str(point_block) + ".bin"
    with open(name, "wb") as f:
        f.write(crsa)
        f.write(caes)
        f.write(tag)
        f.write(ctext)
    point_block += 1
    UpdateNumBlock()

def CreateBlock(str):
    recipent_key = RSA.import_key(
        open("public_key.pem").read()
    )
    session_key = get_random_bytes(16)
    cipher_rsa = PKCS1_OAEP.new(recipent_key)
    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    data = str.encode("utf-8")
    ciphertext, tag = cipher_aes.encrypt_and_digest(data)
    AddBlock(cipher_rsa.encrypt(session_key), ciphertext, tag, cipher_aes.nonce)


def CreateKeys():
    global code
    key = RSA.generate(2048)

    encrypted_key = key.exportKey(
        passphrase=code,
        pkcs = 8,
        protection = "scryptAndAES128-CBC"
    )
    with open("private_key.bin", "wb") as f:
        f.write(encrypted_key)

    with open("public_key.pem", "wb") as f:
        f.write(key.publickey().exportKey())

#db_connect = sqlite3.connect(NAME_BASE)
#cursor = db_connect.cursor()

def GetHashString(str):
    str = str.encode("utf-8")
    sha = hashlib.md5(str).hexdigest()
    return sha

def CreateSystemBase():
    try:
        db_connect = sqlite3.connect(NAME_BASE)
        cursor = db_connect.cursor()
        create_query = '''CREATE TABLE system (
                        name TEXT,
                        value INTEGER)
        '''
        cursor.execute(create_query)
        db_connect.commit()
        print("Системная таблица создана!")
    except sqlite3.Error as error:
        print("Ошибка при создании таблицы новостей SQLite: ", error)
    finally:
        if (db_connect):
            db_connect.close()   

def UpdateNumBlock():
    global point_block
    try:
        db_connect = sqlite3.connect(NAME_BASE)
        cursor = db_connect.cursor()
        news_query = '''UPDATE system
                    SET value = ? 
                    WHERE name = ?
        '''
        cursor.execute(news_query, (point_block, "point_block"))
        db_connect.commit()
    except sqlite3.Error as error:
        print("Ошибка при обновлении номера блока SQLite: ", error)
    finally:
        if (db_connect):
            db_connect.close()  

def GetNumberBlock():
    try:
        db_connect = sqlite3.connect(NAME_BASE)
        cursor = db_connect.cursor()
        db_query = ''' SELECT * FROM system
                    WHERE name = ?
        '''
        cursor.execute(db_query, [("point_block")])
        news = cursor.fetchall()
        return news

    except sqlite3.Error as error:
        print("Ошибка при загрузке номера блока SQLite: ", error)
    finally:
        if (db_connect):
            db_connect.close()

def main():
    #CreateSystemBase()
    #CreateKeys()
    global point_block
    point_block = int(GetNumberBlock()[0][1])
    blockdata = {
        "number": point_block,
        "from": "generic",
        "to": "generic",
        "type": "generic",
        "count": 1000000
    }
    bdata = "num: " + str(blockdata['number']) + ", from: " + str(blockdata['from']) + ", to: " + str(blockdata['to']) + ", type: " + str(blockdata['type']) + ", count: " + str(blockdata['count'])
    CreateBlock(bdata) 
    blockinfo = TranslateBlockInfo(DecryptBlock()) 
    print(blockinfo)


if __name__ == "__main__":
    main()
