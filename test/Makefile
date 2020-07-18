
INC = -I..
LIBS = -L.. -lnetgpu
CFLAGS = -g -Wall $(INC) $(DEFINES)

targets := memarea context socket netqueue

all: $(targets)

%: %.c
	$(QUIET_CC)$(CC) $(CFLAGS) -o $@ $< $(LIBS)

objs := $(patsubst %,%.o,$(targets))

clean:
	rm -f $(targets) $(objs)

test: all
	./run.sh
