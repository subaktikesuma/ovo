MODULE = ovo

obj-m :=$(MODULE).o
$(MODULE)-objs += core.o
$(MODULE)-objs += mmuhack.o
$(MODULE)-objs += kkit.o
$(MODULE)-objs += peekaboo.o
$(MODULE)-objs += memory.o
$(MODULE)-objs += server.o

EXTRA_CFLAGS += -fno-pic
EXTRA_CFLAGS += -DHIDE_SELF_MODULE=0	# 是否在模块表中移除自己
EXTRA_CFLAGS += -DBUILD_REMAP=0	# 是否编译内存重映射API（不稳定）
EXTRA_CFLAGS += -DINJECT_SYSCALLS=0	# 是否注入SYSCALL开启更多功能

all:
	make -C $(KDIR) EXTRA_CFLAGS="$(EXTRA_CFLAGS)" M=$(PWD) modules

clean:
	make -C $(KDIR) M=$(PWD) clean