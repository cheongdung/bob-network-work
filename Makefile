CC = gcc
CFLAGS = -Wall -Wextra

all: sum-nbo

sum-nbo: sum-nbo.c
	$(CC) $(CFLAGS) -o sum-nbo sum-nbo.c

clean:
	rm -f sum-nbo
