import sqlite3
from pathlib import Path
from decimal import Decimal

files = []

for f in Path("./plain"):
    files.append(f.name.replain("_plain.txt",""));

conn = sqlite3.connect("result.db")

cur = conn.cursor()

for f in files:
    cur.execute(f"CREATE TABLE {f} (len INTEGER, crypt_time(ms) REAL, plain_time(ms) REAL, ture TEXT);")
    lines = []
    aver_len = 0
    aver_ct = Decimal(0)
    aver_pt = Decimal(0)
    with open(f"./plain/{f}_plain.txt","r",encoding="utf-8") as fp:
        with open(f"./crypt/{f}_crypt.txt","r",encoding="utf-8") as fc:
            plines = fp.readlines()
            clines = fc.readlines()
            for i in range(len(clines)):
                len = len(plines[i].split("|")[0])
                pr = plines[i].split("|")[2]

                pt = Decimal(plines[i].split("|")[1].replace("s",""))*1000
                ct = Decimal(clines[i].split("|")[1].replace("s",""))*1000
                aver_len += len
                aver_ct += ct
                aver_pt += pt
                lines.append((len,ct,pt,pr))
            aver_len /= len(lines)
            aver_ct /= len(lines)
            aver_pt /= len(lines)
            lines.append((aver_len,aver_ct,aver_pt,""))
cur.executemany(f"INSERT INTO {f} VALUES (?,?,?,?);",lines)
conn.commit()