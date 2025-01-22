MODULE = ovo

obj-m :=$(MODULE).o
$(MODULE)-objs += core.o
$(MODULE)-objs += mmuhack.o
$(MODULE)-objs += kkit.o
$(MODULE)-objs += peekaboo.o
$(MODULE)-objs += memory.o

all:
	make -C $(KDIR) EXTRA_CGLAGS=-fno-pic M=$(PWD) modules

clean:
	make -C $(KDIR) M=$(PWD) clean