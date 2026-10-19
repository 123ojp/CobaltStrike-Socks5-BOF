BOFNAME := socks5

CC_x64 := x86_64-w64-mingw32-gcc
CC_x86 := i686-w64-mingw32-gcc

CFLAGS := -Os -c -DBOF -fno-jump-tables -fno-stack-protector -fno-asynchronous-unwind-tables -Wall
LDFLAGS :=

all: $(BOFNAME).x64.o

$(BOFNAME).x64.o: entry.c beacon.h bofdefs.h
	$(CC_x64) $(CFLAGS) -o $@ entry.c

x86: $(BOFNAME).x86.o

$(BOFNAME).x86.o: entry.c beacon.h bofdefs.h
	$(CC_x86) $(CFLAGS) -o $@ entry.c

clean:
	rm -f $(BOFNAME).x64.o $(BOFNAME).x86.o

.PHONY: all x86 clean
