import random

charList = "0123456789ABCDEF"

with open("key.txt","w",encoding="utf-8") as fk:
    for i in range(2,8194,2):
        key = ""
        for j in range(0,64):
            key = key + str(random.choice(charList))
        fk.write(key + "\n")

with open("plain.txt","w",encoding="utf-8") as fp:
    for i in range(2,8194,2):
        plain = "";
        for j in range(0,i):
            plain = plain + str(random.choice(charList))
        fp.write(plain + "\n")
