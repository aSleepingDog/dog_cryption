import random
import tqdm
#由于python在整除时向负无穷取整 而不是C++中按0取整 所以不对负数做测试
with open("inputA.txt",'w',encoding='utf-8') as fa:
    with open("inputB.txt",'w',encoding='utf-8') as fb:
        for i in tqdm.tqdm(range(1,4095)):
            if random.randint(0,1)==1:
                fa.write('-')
            fa.write(str(random.randint(1,9)))
            for j in range(1,i+1):
                fa.write(str(random.randint(0,9)))
            fa.write("\n")
            
            b_len = random.randint(1,i)
            if random.randint(0,1)==1:
                fb.write('-')
            fb.write(str(random.randint(1,9)))
            for j in range(1,b_len):
                fb.write(str(random.randint(0,9)))
            fb.write("\n")