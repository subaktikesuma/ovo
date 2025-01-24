MODULE = ovo

obj-m :=$(MODULE).o
$(MODULE)-objs += core.o
$(MODULE)-objs += mmuhack.o
$(MODULE)-objs += kkit.o
$(MODULE)-objs += peekaboo.o
$(MODULE)-objs += memory.o

EXTRA_CFLAGS = -fno-pic
EXTRA_CFLAGS += -DHIDE_SELF_MODULE=0

all:
	make -C $(KDIR) EXTRA_CFLAGS="$(EXTRA_CFLAGS)" M=$(PWD) modules

clean:
	make -C $(KDIR) M=$(PWD) clean