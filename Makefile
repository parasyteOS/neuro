obj-y += ecdsa.o
obj-y += core.o
obj-y += tsu.o
obj-y += ioctl/

ccflags-y += -I$(srctree)/drivers/terminalsu/include
ccflags-y += -D TSU_PUB_KEY=$(TSU_PUB_KEY)
