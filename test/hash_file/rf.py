import os
import random

def single_random_file(file_path, min_size_b, max_size_b):
    file_size = random.randint(min_size_b, max_size_b)
    random_bytes = os.urandom(file_size)
    with open(file_path, 'wb') as file:
        file.write(random_bytes)

for i in range(0,8):
    single_random_file(f"./ori_plain_file/{i}.txt",2**10,2**20)