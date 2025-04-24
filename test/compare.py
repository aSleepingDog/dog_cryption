def compare_files(file1_path, file2_path):
    # 读取文件并去除每行的换行符
    with open(file1_path, 'r') as f1:
        lines1 = [line.rstrip('\n') for line in f1]
    with open(file2_path, 'r') as f2:
        lines2 = [line.rstrip('\n') for line in f2]

    max_len = max(len(lines1), len(lines2))
    differences = []
    
    # 逐行比较内容
    for i in range(max_len):
        line1 = lines1[i] if i < len(lines1) else ''
        line2 = lines2[i] if i < len(lines2) else ''
        if line1 != line2:
            differences.append((i + 1, line1, line2))  # 行号从1开始
    
    return differences

# 示例使用
if __name__ == "__main__":
    file1 = input("请输入第一个文件路径: ")
    file2 = input("请输入第二个文件路径: ")
    
    diffs = compare_files(file1, file2)
    
    for diff in diffs:
        line_num, line1, line2 = diff
        print(f"第{line_num}行不同:")
        print(f"File1: {line1}")
        print(f"File2: {line2}\n")