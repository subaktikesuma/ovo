MODULE = ovo

obj-m :=$(MODULE).o
$(MODULE)-objs += core.o
$(MODULE)-objs += mmuhack.o

all:
	make -C $(KDIR) EXTRA_CGLAGS=-fno-pic M=$(PWD) modules

clean:
	make -C $(KDIR) M=$(PWD) clean