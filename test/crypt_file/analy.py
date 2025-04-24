from pathlib import Path
import filecmp
from decimal import ROUND_HALF_UP, Decimal
import sqlite3

db = Path("./result.db")
if db.exists():
    db.unlink()

conn = sqlite3.connect("result.db")

cur = conn.cursor()


dirList = [str(p) for p in Path("./result").iterdir() if p.is_dir()]
plain_files = [str(p) for p in Path("./ori_plain_file").iterdir() if p.is_file()]


for dir in dirList:
    sqlline = []
    cur.execute(f"CREATE TABLE IF NOT EXISTS {dir.split("\\")[-1]} (len INTEGER, `crypt_time(ms)` REAL, `plain_time(ms)` REAL, ture TEXT);")
    with open(f"{dir}/time_record.txt", "r") as ft:
        lines = ft.readlines()
        cplain_files = [str(p) for p in Path(dir+"/plain").iterdir() if p.is_file()]
        for i in range(1,len(lines)):
            result = ""
            if filecmp.cmp(cplain_files[i-1],plain_files[i-1],False):
                result = "TRUE"
            else:
                result = "FALSE"
            size = lines[i].strip().split("|")[0]
            ct = Decimal(lines[i].strip().split("|")[1].replace("s",""))*1000
            st = Decimal(lines[i].strip().split("|")[2].replace("s",""))*1000
            sqlline.append((size,str(ct),str(st),result))
    cur.executemany(f"INSERT INTO {dir.split("\\")[-1]} VALUES (?,?,?,?)", sqlline)

conn.commit()