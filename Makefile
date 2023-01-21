CC=gcc
CFLAGS=-Wall -static
OBJ = bin
LIB = lib
SRC = src
OBJS = $(OBJ)/chromestealer.o $(OBJ)/sqlite3.o
LDFLAGS = -lShlwapi -lCrypt32 -lbcrypt

all: chromestealer

chromestealer: $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) $(LDFLAGS) -o chromestealer

$(OBJ)/sqlite3.o: $(LIB)/sqlite3.c
	$(CC) $(CFLAGS) -c lib/sqlite3.c -o $@

$(OBJ)/chromestealer.o: $(SRC)/chromestealer.c
	$(CC) $(FLAGS) -c src/chromestealer.c -o $@

clean:
	rm chromestealer $(OBJ)/chromestealer.o $(OBJ)/sqlite3.o