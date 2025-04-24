import time

with open("input_bin.txt", "r", encoding="utf-8") as fb:
   with open("output_b2h_py.txt",'w',encoding="utf-8") as fb2h:
       with open("output_b2d_py.txt",'w',encoding="utf-8") as fb2d:
           total_time_input=0.0
           total_time_output_b2h=0.0
           total_time_output_b2d=0.0
           for str in fb.readlines():
               start = time.time()
               n=int(str,2)
               end = time.time()
               total_time_input += end - start
               
               start = time.time()
               if n<0:
                n_str_hex=format(-n,'X')
                if len(n_str_hex)%2==1:
                   n_str_hex='0'+n_str_hex
                n_str_hex='-'+n_str_hex
               else:
                n_str_hex=format(n,'X')
                if len(n_str_hex)%2==1:
                   n_str_hex='0'+n_str_hex
               end = time.time()
               total_time_output_b2h += end - start
               fb2h.write(n_str_hex+'\n')
               
               start = time.time()
               n_str_dec=format(n,'d')
               end = time.time()
               total_time_output_b2d += end - start
               fb2d.write(n_str_dec+'\n')

           fb2h.write(f"input_time:{total_time_input*1000}ms\n")
           fb2h.write(f"output_time:{total_time_output_b2h*1000}ms")

           fb2d.write(f"input_time:{total_time_input*1000}ms\n")
           fb2d.write(f"input_time:{total_time_output_b2d*1000}ms")
           
with open("input_oct.txt", "r", encoding="utf-8") as fo:
   with open("output_o2h_py.txt",'w',encoding="utf-8") as fo2h:
       with open("output_o2d_py.txt",'w',encoding="utf-8") as fo2d:
           total_time_input=0.0
           total_time_output_o2h=0.0
           total_time_output_o2d=0.0
           for str in fo.readlines():
               start = time.time()
               n=int(str,8)
               end = time.time()
               total_time_input += end - start

               start = time.time()
               if n<0:
                n_str_hex=format(-n,'X')
                if len(n_str_hex)%2==1:
                   n_str_hex='0'+n_str_hex
                n_str_hex='-'+n_str_hex
               else:
                n_str_hex=format(n,'X')
                if len(n_str_hex)%2==1:
                   n_str_hex='0'+n_str_hex
               end = time.time()
               total_time_output_o2h += end - start
               fo2h.write(n_str_hex+'\n')

               start = time.time()
               n_str_dec=format(n,'d')
               end = time.time()
               total_time_output_o2d += end - start
               fo2d.write(n_str_dec+'\n')

           fo2h.write(f"input_time:{total_time_input*1000}ms\n")
           fo2h.write(f"output_time:{total_time_output_o2h*1000}ms")

           fo2d.write(f"input_time:{total_time_input*1000}ms\n")
           fo2d.write(f"input_time:{total_time_output_o2d*1000}ms")

with open("input_dec.txt", "r", encoding="utf-8") as fh:
    with open("output_d2h_py.txt",'w',encoding="utf-8") as fd2h:
        with open("output_d2d_py.txt",'w',encoding="utf-8") as fd2d:
            total_time_input=0.0
            total_time_output_d2h=0.0
            total_time_output_d2d=0.0
            for str in fh.readlines():
                start = time.time()
                n=int(str,10)
                end = time.time()
                total_time_input += end - start

                start = time.time()
                if n<0:
                    n_str_hex=format(-n,'X')
                    if len(n_str_hex)%2==1:
                        n_str_hex='0'+n_str_hex
                    n_str_hex='-'+n_str_hex
                else:
                    n_str_hex=format(n,'X')
                    if len(n_str_hex)%2==1:
                        n_str_hex='0'+n_str_hex
                end = time.time()
                total_time_output_d2h += end - start
                fd2h.write(n_str_hex+'\n')

                start = time.time()
                n_str_dec=format(n,'d')
                end = time.time()
                total_time_output_d2d += end - start
                fd2d.write(n_str_dec+'\n')

            fd2h.write(f"input_time:{total_time_input*1000}ms\n")
            fd2h.write(f"output_time:{total_time_output_d2h*1000}ms")

            fd2d.write(f"input_time:{total_time_input*1000}ms\n")
            fd2d.write(f"input_time:{total_time_output_d2d*1000}ms")

with open("input_hex.txt", "r", encoding="utf-8") as fh:
    with open("output_h2h_py.txt",'w',encoding="utf-8") as fh2h:
        with open("output_h2d_py.txt",'w',encoding="utf-8") as fh2d:
            total_time_input=0.0
            total_time_output_h2h=0.0
            total_time_output_h2d=0.0
            for str in fh.readlines():
                start = time.time()
                n=int(str,16)
                end = time.time()
                total_time_input += end - start

                start = time.time()
                if n<0:
                    n_str_hex=format(-n,'X')
                    if len(n_str_hex)%2==1:
                        n_str_hex='0'+n_str_hex
                    n_str_hex='-'+n_str_hex
                else:
                    n_str_hex=format(n,'X')
                    if len(n_str_hex)%2==1:
                        n_str_hex='0'+n_str_hex
                end = time.time()
                total_time_output_h2h += end - start
                fh2h.write(n_str_hex+'\n')

                start = time.time()
                n_str_dec=format(n,'d')
                end = time.time()
                total_time_output_h2d += end - start
                fh2d.write(n_str_dec+'\n')

            fh2h.write(f"input_time:{total_time_input*1000}ms\n")
            fh2h.write(f"output_time:{total_time_output_h2h*1000}ms")

            fh2d.write(f"input_time:{total_time_input*1000}ms\n")
            fh2d.write(f"input_time:{total_time_output_h2d*1000}ms")