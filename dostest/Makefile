.PHONY: all clean install
.SUFFIXES: .s .com

SOURCES := $(wildcard *.s)
OBJS := $(SOURCES:.s=.com)
CFLAGS := 
LDFLAGS := -nostdlib -T dos_com.ld

all: $(OBJS)

clean:
	rm -f $(OBJS)

install: all
	cp $(OBJS) ~/.dosboxdrv
	../dosbox-0.74-3-dbg

.s.com:
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)
	objdump -b binary -m i386 -M i8086 --adjust-vma=0x100 -D $@
