CC = gcc
CFLAGS = -Wall -O2

# Default target
all: twig

# Build twig from twig.c
twig: twig.c
	$(CC) $(CFLAGS) -o twig twig.c

# Clean build artifacts
clean:
	rm -f twig *.o
