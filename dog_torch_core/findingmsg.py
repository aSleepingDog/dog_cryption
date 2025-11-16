import pathlib
import re

root = "./src"
for file in pathlib.Path(root).rglob("*.cpp"):
    with open(file, "r") as f:
        context = f.read()
        context = re.sub(r"//.*\n", "", context)  # Remove single-line comments
        context = re.sub(r"/\*.*?\*/", "", context, flags=re.DOTALL)  # Remove multi-line comments
        restr = r"(DOG_EXCEPTION_MSG_OPINION|DOG_EXCEPTION)\(.*?\"(.*?)\".*?\)"
        result = re.findall(restr, context)
        for msg in result:
            print(msg[1].split("\\n"))