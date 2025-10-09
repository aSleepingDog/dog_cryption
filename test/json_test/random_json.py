import json
import random
from faker import Faker

def rand_str():
    fake = Faker(locale=['zh_CN','zh_TW', 'en_US','en_GB','ja_JP', 'ko_KR','de_DE','ko_KR','fr_FR','es_ES'])
    return fake.sentence(nb_words=6, variable_nb_words=True, ext_word_list=None)

def rand_number():
    return random.randint(0, 10**15)

def random_jsonvalue(type : int, depth :int):
    if type == 0:
        return None
    elif type == 1:
        if random.randint(0, 1) == 0:
            return True
        else:
            return False
    elif type == 2:
        return rand_number()
    elif type == 3:
        return rand_str()
    elif type == 4:
        rand_array = []
        for i in range(random.randint(1, 10)):
            if depth < 5:
                rand_array.append(random_jsonvalue(random.randint(0, 5),depth+1))
            else:
                rand_array.append(random_jsonvalue(random.randint(0, 3),depth+1))
        return rand_array
    elif type == 5:
        rand_dict = {}
        for i in range(random.randint(1, 10)):
            if depth < 5:
                rand_dict[random_jsonvalue(3,0)] = random_jsonvalue(random.randint(0, 5),depth+1)
            else:
                rand_dict[random_jsonvalue(3,0)] = random_jsonvalue(random.randint(0, 3),depth+1)
        return rand_dict

for i in range(0,10):
    with open(f'./json_file/{i}.json', 'w', encoding='utf-8') as f:
        res = ""
        if i < 5:
            res = random_jsonvalue(5,0)
        else:
            res = random_jsonvalue(4,0)
        res_str = json.dumps(res, ensure_ascii=False, indent=4)
        f.write(res_str)