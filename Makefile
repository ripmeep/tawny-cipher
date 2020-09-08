OBJS     = main.o
SOURCE	 = main.c
HEADER	 = tawny.h
OUT	 = tawny_cipher
CC	 = gcc
FLAGS	 = -g -c
LFLAGS	 = -lcrypto

all: $(OBJS)
	$(CC) -g $(OBJS) -o $(OUT) $(LFLAGS) -v

main.o: main.c
	$(CC) $(FLAGS) main.c -lcrypto -v

clean:
	rm -f $(OBJS) $(OUT)
