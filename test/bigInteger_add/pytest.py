import tqdm

list_a=[]
list_b=[]
list_add=[]
list_selfadd=[]
list_sub=[]
list_selfsub=[]

with open("inputA.txt", "r",encoding='utf-8') as fa:
    for a in fa.readlines():
        list_a.append(int(a,10))

with open("inputB.txt", "r",encoding='utf-8') as fb:
    for b in fb.readlines():
        list_b.append(int(b,10))

total_add_time=0
total_selfadd_time=0
total_sub_time=0
total_selfsub_time=0

for i in tqdm.tqdm(range(len(list_a))):
    import time

    #加法
    start = time.time()
    add=list_a[i]+list_b[i]
    end = time.time()
    total_add_time += end - start
    list_add.append(add)

    #自加
    a=list_a[i]
    b=list_b[i]
    start = time.time()
    a+=b
    end = time.time()
    total_selfadd_time += end - start
    list_selfadd.append(a==list_add[i])

    #减法
    start = time.time()
    sub=list_a[i]-list_b[i]
    end = time.time()
    total_sub_time += end - start
    list_sub.append(sub)

    #自减
    a=list_a[i]
    b=list_b[i]
    start = time.time()
    a-=b
    end = time.time()
    total_selfsub_time += end - start
    list_selfsub.append(a==list_sub[i])


with open("output_add_py.txt", "w",encoding='utf-8') as fadd:
    for ci in range(len(list_add)):
        fadd.write(f"{list_add[ci]}-{list_selfadd[ci]}\n")
    fadd.write(f"add_time:{total_add_time*1000}ms\n")
    fadd.write(f"selfadd_time:{total_selfadd_time*1000}ms")

with open("output_sub_py.txt", "w",encoding='utf-8') as fsub:
    for ci in range(len(list_sub)):
        fsub.write(f"{list_sub[ci]}-{list_selfsub[ci]}\n")
    fsub.write(f"sub_time:{total_sub_time*1000}ms\n")
    fsub.write(f"selfsub_time:{total_selfsub_time*1000}ms")