import os
import hashlib
from pathlib import Path
import sqlite3
from decimal import Decimal

def calculate_hash(file_path,algorithm):
    if algorithm == "SM3":
        from gmssl import sm3
        files = [str(p) for p in Path(file_path).iterdir() if p.is_file()]
        res = []
        for file in files:
            with open(file, "rb") as f:
                res.append(sm3.sm3_hash(list(f.read())).upper())
        return res
    files = [str(p) for p in Path(file_path).iterdir() if p.is_file()]
    res = []
    for file in files:
        if algorithm == "SHA2_256":
            hash_obj = hashlib.sha256()
        elif algorithm == "SHA2_224":
            hash_obj = hashlib.sha224()
        elif algorithm == "SHA2_384":
            hash_obj = hashlib.sha384()
        elif algorithm == "SHA2_512":
            hash_obj = hashlib.sha512()
        with open(file, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                hash_obj.update(byte_block)
        res.append(hash_obj.hexdigest().upper())
    return res
    

if __name__ == "__main__":

    db = Path("./result.db")
    if db.exists():
        db.unlink()

    conn = sqlite3.connect("result.db")
    cur = conn.cursor()

    hash_algorithms = ["SHA2_256", "SHA2_224", "SHA2_384", "SHA2_512", "SM3"]
    for hash_type in hash_algorithms:
        result = calculate_hash("./ori_plain_file", f"{hash_type}")
        with open(f"./{hash_type}.txt","r",encoding="utf-8") as f:
            cur.execute(f"CREATE TABLE {hash_type} (len INTEGER, `hash_time(ms)` REAL, ture TEXT);")
            lines = f.readlines()
            dblines = []
            for i in range(len(lines)):
                size = lines[i].strip().split("|")[0]
                tmpres0 = lines[i].strip().split("|")[1]
                tmpres1 = result[i]
                time = str(Decimal(lines[i].strip().split("|")[2].replace("s",""))*1000)
                res = ""
                if tmpres0 == tmpres1:
                    res = "TRUE"
                else:
                    res = "FALSE"
                dblines.append((size,time,res))
            cur.executemany(f"INSERT INTO {hash_type} VALUES (?,?,?)", dblines)
    conn.commit()