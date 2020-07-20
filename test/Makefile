
include ../compile.mk

INC = -I..
LIBS = -L.. -lnetgpu $(EXTRA_LIBS)
CFLAGS = -g $(OPTS) $(INC) $(DEFINES)

targets := memarea context dmamap socket netqueue

all: $(targets)

%: %.c
	$(QUIET_CC)$(CC) $(CFLAGS) -o $@ $< $(LIBS)

objs := $(patsubst %,%.o,$(targets))

clean:
	rm -f $(targets) $(objs)

test: all
	./run.sh
