with open("output_divide_Knuth_C.txt", "r",encoding='utf-8') as fc:
    with open("output_divide_py.txt", "r",encoding='utf-8') as fp:
        lc=fc.readlines()
        lp=fp.readlines()
        size = len(lc)
        for i in range(size):
            if lc[i]!=lp[i]:
                print(i+1)
                print("C :"+lc[i],end="")
                print("py:"+lp[i],end="")
                print("   ",end="")
                for j in range(min(len(lc[i]),len(lp[i]))):
                    if lc[i][j]==lp[i][j]:
                        print("-",end="")
                    else:
                        print("^",end="")
                print()