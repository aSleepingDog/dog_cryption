import random
import tqdm

with open("input_bin.txt","w",encoding="utf-8") as fb:
    for i in tqdm.tqdm(range(1,4096)):
        if random.randint(0,1)==1:
            fb.write("-")
        for j in range(1,i+1):
            fb.write(str(random.randint(0,1)))
        fb.write("\n")

with open("input_oct.txt","w",encoding="utf-8") as fo:
    for i in tqdm.tqdm(range(1,2048)):
        if random.randint(0,1)==1:
            fo.write("-")
        for j in range(1,i+1):
            fo.write(str(random.randint(0,7)))
        fo.write("\n")

with open("input_dec.txt","w",encoding="utf-8") as fd:
    for i in tqdm.tqdm(range(1,1024)):
        if random.randint(0,1)==1:
            fd.write("-")
        for j in range(1,i+1):
            fd.write(str(random.randint(0,9)))
        fd.write("\n")

with open("input_hex.txt","w",encoding="utf-8") as fh:
    chars="0123456789ABCDEF"
    for i in tqdm.tqdm(range(1,512)):
        if random.randint(0,1)==1:
            fh.write("-")
        for j in range(1,i+1):
            fh.write(str(random.choice(chars)))
        fh.write("\n")