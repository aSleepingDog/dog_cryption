import sqlite3

def find_false_entries(db_path):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%';")
    tables = [t[0] for t in cursor.fetchall()]
    
    for table in tables:
        try:
            print(f"表{table}")
            cursor.execute(f"SELECT * FROM sqlite_master WHERE name='{table}'")
            columns = ((cursor.fetchall()[0])[-1].split(f"CREATE TABLE {table} (")[1])[0:-1].split(", ")
            fmtStr = ""
            for i in range(len(columns)-1):
                print(f"{columns[i]}",end="|")
                fmtStr += "{:<" + str(len(columns[i])) + "}|"
            print(f"{columns[-1]}")
            fmtStr += "{:<" + str(len(columns[-1])) + "}"
            cursor.execute(f'SELECT * FROM "{table}" WHERE "true"="FALSE"')
            rows = cursor.fetchall()

            for row in rows:
                print(fmtStr.format(*row))

                
        except sqlite3.OperationalError as e:
            continue

    conn.close()

if __name__ == "__main__":
    path = input("请输入SQLite3数据库路径:")
    find_false_entries(path) 