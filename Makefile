CC=gcc
CFLAGS=-Wall -static
OBJDIR = bin
LIB = lib
SRC = src
OBJS = $(OBJDIR)/chromestealer.o $(OBJDIR)/sqlite3.o
LDFLAGS = -lShlwapi -lCrypt32 -lbcrypt

all: chromestealer

chromestealer: $(OBJDIR) | $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) $(LDFLAGS) -o chromestealer

$(OBJDIR):
	mkdir $(OBJDIR)

$(OBJDIR)/sqlite3.o: $(LIB)/sqlite3.c
	$(CC) $(CFLAGS) -c lib/sqlite3.c -o $@

$(OBJDIR)/chromestealer.o: $(SRC)/chromestealer.c
	$(CC) $(FLAGS) -c src/chromestealer.c -o $@

.PHONY: clean

clean:
	del /q $(OBJDIR)
	del chromestealer.exe
