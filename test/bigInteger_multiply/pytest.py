import tqdm
import sys

sys.set_int_max_str_digits(8200)

list_a=[]
list_b=[]
list_multiply=[]

with open("inputA.txt", "r",encoding='utf-8') as fa:
    for a in fa.readlines():
        list_a.append(int(a,10))

with open("inputB.txt", "r",encoding='utf-8') as fb:
    for b in fb.readlines():
        list_b.append(int(b,10))

total_multiply_time=0

for i in tqdm.tqdm(range(len(list_a))):
    import time

    start = time.time()
    multiply=list_a[i]*list_b[i]
    end = time.time()
    total_multiply_time += end - start
    list_multiply.append(multiply)

with open("output_multiply_py.txt", "w",encoding='utf-8') as fmultiply:
    for ci in range(len(list_multiply)):
        l=format(list_multiply[ci], 'd')
        fmultiply.write(l+'\n')
    fmultiply.write(f"multiply_time:{total_multiply_time*1000}ms\n")