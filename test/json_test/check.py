import json

def read_json_file(file_path):
    with open(file_path, 'r', encoding='utf-8') as file:
        return json.load(file)

for i in range(0,10):
    with open(f'./json_file/{i}.json', 'r', encoding='utf-8') as f1:
        with open(f'./cpp_res/{i}.json', 'r', encoding='utf-8') as f2:
            json1 = json.load(f1)
            json2 = json.load(f2)
            if json1 == json2:
                print(f'{i} is equal')
            else:
                print(f'{i} is not equal')