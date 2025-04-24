import hashlib

import sqlite3
from pathlib import Path
from decimal import ROUND_HALF_UP, Decimal

def hex_to_string(hex_str):
    try:
        byte_str = bytes.fromhex(hex_str)
        return byte_str
    except ValueError as e:
        print(f"输入的十六进制字符串无效: {e}")
        return None

def calculate_hash(byte_str, algorithm):
    if algorithm == "SHA2_256":
        hash_obj = hashlib.sha256()
    elif algorithm == "SHA2_224":
        hash_obj = hashlib.sha224()
    elif algorithm == "SHA2_384":
        hash_obj = hashlib.sha384()
    elif algorithm == "SHA2_512":
        hash_obj = hashlib.sha512()
    elif algorithm == "SM3":
        from gmssl import sm3
        byte_array = bytearray(byte_str)
        hash_obj = sm3.sm3_hash(byte_array)
        return hash_obj
    else:
        print(f"不支持的算法: {algorithm}")
        return None
    hash_obj.update(byte_str)
    return hash_obj.hexdigest()

if __name__ == "__main__":

    db = Path("./result.db")
    if db.exists():
        db.unlink()
    
    conn = sqlite3.connect("result.db")

    cur = conn.cursor()

    hash_list=["SHA2_224","SHA2_256","SHA2_384","SHA2_512","SM3"]

    with open("plain.txt","r",encoding="utf-8") as fp:
        plains = fp.readlines()

        for hash in hash_list:
            with open(f"{hash}.txt","r",encoding="utf-8") as fs:
                cur.execute(f"CREATE TABLE {hash} (len INTEGER, `hash_time(ms)` REAL, ture TEXT);")
                srs = fs.readlines()
                tst = Decimal(0)
                lines = []
                for i in range(len(plains)):
                    plain = plains[i].strip()
                    sr = srs[i].strip().split("|")[0]
                    st = Decimal(srs[i].strip().split("|")[1].replace("s",""))*1000
                    tst += st
                    byte_str = hex_to_string(plain)
                    hash_value = calculate_hash(byte_str, f"{hash}").upper()
                    hsr = ""
                    if hash_value != sr:
                        hsr = "FALSE"
                    else:
                        hsr = "TRUE"
                    lines.append((len(plain),str(st.quantize(Decimal('0.01'))),hsr))
                lines.append((0,str(tst.quantize(Decimal('0.01'))),""))
                cur.executemany(f"INSERT INTO {hash} VALUES (?,?,?)",lines)
    conn.commit()