import sqlite3
import hashlib
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP

NAME_BASE = "system.db"
point_block = 0
account_id = 0
medcard_id = 0
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

def DecryptBlock(block):
    global code
    name = "block_" + str(block) + ".bin"
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
    point_block = int(GetNumberBlock()[0][1])
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

def CreateAccountsBase():
    try:
        db_connect = sqlite3.connect(NAME_BASE)
        cursor = db_connect.cursor()
        create_query = '''CREATE TABLE accounts (
                        name TEXT,
                        login TEXT, 
                        password INTEGER,
                        ID INTEGER,
                        medid INTEGER)
        '''
        cursor.execute(create_query)
        db_connect.commit()
        print("Таблица с данными пользователей создана!")
    except sqlite3.Error as error:
        print("Ошибка при создании таблицы аккаунтов SQLite: ", error)
    finally:
        if (db_connect):
            db_connect.close()   

def GetAccountInfo(login=None, id=None):
    if login is not None:
        try:
            print("Проверка логина")
            db_connect = sqlite3.connect(NAME_BASE)
            cursor = db_connect.cursor()
            db_query = ''' SELECT * FROM accounts
                        WHERE login = ?
            '''
            cursor.execute(db_query, [(login)])
            AccountInfo = cursor.fetchall()
            return AccountInfo

        except sqlite3.Error as error:
            print("Ошибка при загрузке аккаунта SQLite: ", error)
        finally:
            if (db_connect):
                db_connect.close()
    elif id is not None:
        try:
            print("Поиск по паролю")
            db_connect = sqlite3.connect(NAME_BASE)
            cursor = db_connect.cursor()
            db_query = ''' SELECT * FROM accounts
                        WHERE ID = ?
            '''
            cursor.execute(db_query, [(id)])
            AccountInfo = cursor.fetchall()
            return AccountInfo

        except sqlite3.Error as error:
            print("Ошибка при загрузке аккаунта SQLite: ", error)
        finally:
            if (db_connect):
                db_connect.close()
def UpdateAccountInfo(id, medid=None):
    if medid is not None:
        try:
            db_connect = sqlite3.connect(NAME_BASE)
            cursor = db_connect.cursor()
            news_query = '''UPDATE accounts
                        SET medid = ? 
                        WHERE ID = ?
            '''
            cursor.execute(news_query, (medid, id))
            db_connect.commit()
        except sqlite3.Error as error:
            print("Ошибка при обновлении номера блока SQLite: ", error)
        finally:
            if (db_connect):
                db_connect.close()  

def CreateAccount(AccountInfo):
    global account_id
    global point_block
    point_block = int(GetNumberBlock()[0][1])
    GetAccountID()
    account = (AccountInfo['name'], AccountInfo['login'], GetHashString(AccountInfo['password']), account_id, int(AccountInfo['type']), 0)
    try:
        db_connect = sqlite3.connect(NAME_BASE)
        cursor = db_connect.cursor()
        account_query = ''' INSERT INTO accounts(name, login, password, ID, type, medid)
                            VALUES (?, ?, ?, ?, ?, ?)
        '''
        cursor.execute(account_query, account)
        db_connect.commit()
        account_id += 1
        UpdateAccountID()
        binfo = "Account ID: " + str(account_id-1) + ". Login: " + str(AccountInfo['login']) + ". Password: " + str(GetHashString(AccountInfo['password']))
        print(binfo)
        blockdata = {
        "number": point_block,
        "from": AccountInfo['login'],
        "to": AccountInfo['login'],
        "type": "createaccount",
        "count": 0,
        "info": str(binfo)
        }
        bdata = "num: " + str(blockdata['number']) + ", from: " + str(blockdata['from']) + ", to: " + str(blockdata['to']) + ", type: " + str(blockdata['type']) + ", count: " + str(blockdata['count']) + ", info: " + str(blockdata['info'])
        CreateBlock(bdata)
    except sqlite3.Error as error:
        print("Ошибка при создании аккаунта SQLite: ", error)
    finally:
        if(db_connect):
            db_connect.close()

def UpdateAccountID():
    global account_id
    try:
        db_connect = sqlite3.connect(NAME_BASE)
        cursor = db_connect.cursor()
        news_query = '''UPDATE system
                    SET value = ? 
                    WHERE name = ?
        '''
        cursor.execute(news_query, (account_id, "account_id"))
        db_connect.commit()
    except sqlite3.Error as error:
        print("Ошибка при обновлении номера аккаунта SQLite: ", error)
    finally:
        if (db_connect):
            db_connect.close()  

def GetAccountID():
    global account_id
    try:
        db_connect = sqlite3.connect(NAME_BASE)
        cursor = db_connect.cursor()
        db_query = ''' SELECT * FROM system
                    WHERE name = ?
        '''
        cursor.execute(db_query, [("account_id")])
        info = cursor.fetchall()
        account_id = int(info[0][1])
        print('[DEBUG] Номер аккаунта обновлён! ID - ', account_id)
    except sqlite3.Error as error:
        print("Ошибка при загрузке номера блока SQLite: ", error)
    finally:
        if (db_connect):
            db_connect.close()

def CreateMedBase():
    try:
        db_connect = sqlite3.connect(NAME_BASE)
        cursor = db_connect.cursor()
        create_query = '''CREATE TABLE medcards (
                        ID INTEGER,
                        created_date TEXT,
                        first_name TEXT, 
                        second_name TEXT,
                        third_name TEXT,
                        birthdate TEXT,
                        history TEXT)
        '''
        cursor.execute(create_query)
        db_connect.commit()
        print("Таблица с мед карточками создана!")
    except sqlite3.Error as error:
        print("Ошибка при создании базы карточек. SqLite: ", error)
    finally:
        if (db_connect):
            db_connect.close()

def CreateMedCard(CardInfo):
    global medcard_id
    medcard_id = int(GetMedID()[0][1])
    global point_block
    point_block = int(GetNumberBlock()[0][1])
    card = (medcard_id,
            str(CardInfo['created_date']),
            str(CardInfo['first_name']),
            str(CardInfo['second_name']),
            str(CardInfo['third_name']),
            str(CardInfo['birthdate']),
            str(CardInfo['history']))
    try:
        db_connect = sqlite3.connect(NAME_BASE)
        cursor = db_connect.cursor()
        account_query = ''' INSERT INTO medcards(ID, created_date, first_name, second_name, third_name, birthdate, history)
                            VALUES (?, ?, ?, ?, ?, ?, ?)
        '''
        cursor.execute(account_query, card)
        db_connect.commit()
        medcard_id += 1
        UpdateMedID()
        binfo = "Med ID: " + str(medcard_id-1) + ". CreatedDate: " + str(CardInfo['created_date']) + ". FirstName: " + str(CardInfo['first_name'] + ". SecondName: " + str(CardInfo['second_name']) + ". ThirdName: " + str(CardInfo['third_name']) + ". Birthdate: " + str(CardInfo['birthdate']))
        print(binfo)
        blockdata = {
        "number": point_block,
        "from": str(medcard_id-1),
        "to": str(medcard_id-1),
        "type": "createmedcard",
        "count": 0,
        "info": str(binfo)
        }
        bdata = "num: " + str(blockdata['number']) + ", from: " + str(blockdata['from']) + ", to: " + str(blockdata['to']) + ", type: " + str(blockdata['type']) + ", count: " + str(blockdata['count']) + ", info: " + str(blockdata['info'])
        CreateBlock(bdata)
    except sqlite3.Error as error:
        print("Ошибка при создании медкарточки SQLite: ", error)
    finally:
        if(db_connect):
            db_connect.close()

def UpdateHistoryMed(id, history, new_history):
    global point_block
    point_block = int(GetNumberBlock()[0][1])
    try:
        db_connect = sqlite3.connect(NAME_BASE)
        cursor = db_connect.cursor()
        news_query = '''UPDATE medcards
                    SET history = ? 
                    WHERE ID = ?
        '''
        cursor.execute(news_query, (str(history), id))
        db_connect.commit()
        binfo = "Med ID: " + str(id) + ". New history ivent: " + str(new_history)
        blockdata = {
        "number": point_block,
        "from": str(id),
        "to": str(id),
        "type": "updatehistory",
        "count": 0,
        "info": str(binfo)
        }
        bdata = "num: " + str(blockdata['number']) + ", from: " + str(blockdata['from']) + ", to: " + str(blockdata['to']) + ", type: " + str(blockdata['type']) + ", count: " + str(blockdata['count']) + ", info: " + str(blockdata['info'])
        CreateBlock(bdata)
    except sqlite3.Error as error:
        print("Ошибка при обновлении истории медкарты SQLite: ", error)
    finally:
        if (db_connect):
            db_connect.close()  

def UpdateMedID():
    global medcard_id
    try:
        db_connect = sqlite3.connect(NAME_BASE)
        cursor = db_connect.cursor()
        news_query = '''UPDATE system
                    SET value = ? 
                    WHERE name = ?
        '''
        cursor.execute(news_query, (str(medcard_id), "medcard_id"))
        db_connect.commit()
    except sqlite3.Error as error:
        print("Ошибка при обновлении номера медкарты SQLite: ", error)
    finally:
        if (db_connect):
            db_connect.close()  

def GetMedID():
    global medcard_id
    try:
        db_connect = sqlite3.connect(NAME_BASE)
        cursor = db_connect.cursor()
        db_query = ''' SELECT * FROM system
                    WHERE name = ?
        '''
        cursor.execute(db_query, [("medcard_id")])
        info = cursor.fetchall()
        return info
        print('[DEBUG] Номер медкарты обновлён! ID - ', medcard_id)
    except sqlite3.Error as error:
        print("Ошибка при загрузке номера блока SQLite: ", error)
    finally:
        if (db_connect):
            db_connect.close()

def GetCardInfo(id=None, first_name=None, second_name=None, third_name=None):
    if id is not None and first_name is None and second_name is None and third_name is None:
        try:
            db_connect = sqlite3.connect(NAME_BASE)
            cursor = db_connect.cursor()
            db_query = ''' SELECT * FROM medcards
                        WHERE ID = ?
            '''
            cursor.execute(db_query, [(id)])
            info = cursor.fetchall()
            if len(info) != 0:
                CardInfo = {
                    'ID': id,
                    'created_date': str(info[0][1]),
                    'first_name': str(info[0][2]),
                    'second_name': str(info[0][3]),
                    'third_name': str(info[0][4]),
                    'birthdate': str(info[0][5]),
                    'history': str(info[0][6])
                }
                return CardInfo
            else:
                return False
        except sqlite3.Error as error:
            print("Ошибка при загрузке медкарты SQLite: ", error)
        finally:
            if (db_connect):
                db_connect.close()
    if id is None and first_name is not None and second_name is not None and third_name is not None:
        try:
            db_connect = sqlite3.connect(NAME_BASE)
            cursor = db_connect.cursor()
            db_query = ''' SELECT * FROM medcards
                        WHERE first_name = ? and second_name = ? and third_name = ?
            '''
            cursor.execute(db_query, [first_name, second_name, third_name])
            info = cursor.fetchone()
            print("[DEBUG] " + str(info))
            if info != None:
                CardInfo = {
                    'ID': int(info[0]),
                    'created_date': str(info[1]),
                    'first_name': str(info[2]),
                    'second_name': str(info[3]),
                    'third_name': str(info[4]),
                    'birthdate': str(info[5]),
                    'history': str(info[6])
                }
                return CardInfo
            else:
                return False
        except sqlite3.Error as error:
            print("Ошибка при загрузке медкарты SQLite: ", error)
        finally:
            if (db_connect):
                db_connect.close()


def main():
    #CreateSystemBase()
    #CreateKeys()
    #global point_block
    #point_block = int(GetNumberBlock()[0][1])
    #blockdata = {
    #    "number": point_block,
    #    "from": "generic",
    #    "to": "generic",
    #    "type": "generic",
    #    "count": 1000000,
    #    "info": "generic block"
    #}
    #bdata = "num: " + str(blockdata['number']) + ", from: " + str(blockdata['from']) + ", to: " + str(blockdata['to']) + ", type: " + str(blockdata['type']) + ", count: " + str(blockdata['count']) + ", info: " + str(blockdata['info'])
    #CreateBlock(bdata) 
    #blockinfo = TranslateBlockInfo(DecryptBlock()) 
    print(DecryptBlock(4))
    #CreateMedBase()
    pass

if __name__ == "__main__":
    main()
