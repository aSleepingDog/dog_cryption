import random
import tqdm

with open("inputA.txt",'w',encoding='utf-8') as fa:
    with open("inputB.txt",'w',encoding='utf-8') as fb:
        for i in tqdm.tqdm(range(1,4095)):
            if random.randint(0,1) == 0:
                fa.write("-")
            if random.randint(0,1) == 0:
                fb.write("-")
            fa.write(str(random.randint(1,9)))
            fb.write(str(random.randint(1,9)))
            for j in range(1,i+1):
                fa.write(str(random.randint(0,9)))
                fb.write(str(random.randint(0,9)))
            fa.write("\n")
            fb.write("\n")