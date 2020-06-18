
cuda := $(shell test -e /usr/local/cuda/bin/nvcc && echo "1")

ifdef cuda
CC = /usr/local/cuda/bin/nvcc
EXTRA_LIBS = -lcuda
DEFINES = -DUSE_CUDA=1
OPTS = -O
else
CC = cc
EXTRA_LIBS =
OPTS = -fPIC -O
endif

#TOOLS_DIR = /root/linux/lib
# UAPI_DIR = uapi
#LINUX_DIR = /root/linux/include
#KERNEL_INC = -I$(TOOLS_DIR) -I$(UAPI_DIR) -I$(LINUX_DIR)
#INC = -I$(IOU_DIR)/include $(KERNEL_INC)
#IOU_LIBS = $(IOU_DIR)/liburing.a 

INC = -I.
LIBS = libbpf.a $(EXTRA_LIBS) -lz -lelf
LIBS += -L. -lnetgpu
CFLAGS = -g $(OPTS) $(INC) $(DEFINES)

lib_SRCS = \
	netgpu_lib.c \

TARGETS = libnetgpu.a

lib_OBJ = $(patsubst %.c,%.o,$(lib_SRCS))
OBJS = $(lib_OBJ)

.PHONY: all
all: $(TARGETS)

libnetgpu.a: $(lib_OBJ)
	$(AR) r $@ $^

clean:
	rm -f $(TARGETS) $(OBJS)
