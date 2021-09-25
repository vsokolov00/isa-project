CC=gcc
CFLAGS=-std=c11 -Wall -Wextra 
OBJ=popcl.o
PROGRAM=popcl

all: $(PROGRAM)

$(PROGRAM): $(OBJ)
	$(CC) $(CFLAGS) $(OBJ) -o $(PROGRAM)

%.o: %.c %.h
	$(CC) $(CFLAGS) $< -c -o $@

clean:
	rm $(OBJ) $(PROGRAM) 2>/dev/null || true
