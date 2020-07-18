
cuda := $(shell test -e /usr/local/cuda/bin/nvcc && echo "1")

ifdef cuda
CC = /usr/local/cuda/bin/nvcc
EXTRA_LIBS = -lcuda
DEFINES = -DUSE_CUDA=1
OPTS = -O
else
CC = cc
EXTRA_LIBS =
OPTS = -Wall -fPIC -O
endif
