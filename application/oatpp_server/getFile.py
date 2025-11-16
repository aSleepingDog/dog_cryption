import pathlib

include = "./include"
src = "./src"

def source_group(path):
    has_children = None
    files = ""
    for file in pathlib.Path(path).iterdir():
        if file.is_dir():
            has_children = True
            source_group(file)
        else:
            file_str = str(file).replace("\\","/") + "\n"
            files += f"    {file_str}"
    if not has_children:
        path_str = f"{path}".replace("\\","\\\\")
        print(f"source_group(\"Header Files\\\\\\\\{path_str}\"\nFILES\n{files})")
source_group(include)
all_files = ""
for file in pathlib.Path(include).rglob("*.h"):
    all_files += f"    {str(file).replace('\\','/')}\n"
for file in pathlib.Path(src).rglob("*.cpp"):
    all_files += f"    {str(file).replace('\\','/')}\n"
print(F"set(OATPP_SRC\n{all_files}\n    main_server.cpp\n)")
a=input()