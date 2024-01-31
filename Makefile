KDIR ?= /lib/modules/$(shell uname -r)/build

all:
	$(MAKE) -C $(KDIR) M=$$PWD

trigger: trigger.c
	gcc -static -o trigger trigger.c

clean:
	$(MAKE) -C $(KDIR) M=$$PWD clean
	rm -f trigger
