import tqdm
import sys

sys.set_int_max_str_digits(8200)

list_a=[]
list_b=[]
list_divide=[]

with open("inputA.txt", "r",encoding='utf-8') as fa:
    for a in fa.readlines():
        list_a.append(int(a,10))

with open("inputB.txt", "r",encoding='utf-8') as fb:
    for b in fb.readlines():
        list_b.append(int(b,10))

total_divide_time=0

for i in tqdm.tqdm(range(len(list_a))):
    import time

    a = list_a[i]
    b = list_b[i]

    start = time.time()
    divide = a//b
    r = a%b
    if divide<0 and r!=0:
        divide+=1
    end = time.time()
    total_divide_time += end - start
    list_divide.append(divide)

def uphex(n):
    m = n
    str = ""
    if n<0:
        n*=-1
    if len("{:X}".format(n))%2==1:
        str = "0"+"{:X}".format(n)
    else:
        str ="{:X}".format(n)
    if m<0:
        str = "-"+str
    return str

with open("output_divide_py.txt", "w",encoding='utf-8') as fdivide:
    for ci in range(len(list_divide)):
        fdivide.write(uphex(list_divide[ci])+"\n")
    fdivide.write(f"divide_time:{total_divide_time*1000}ms\n")