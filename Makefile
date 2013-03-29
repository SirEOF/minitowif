CC		= gcc
RC		= windres
CFLAGS	= -I. -L. -Wl,--subsystem,windows -s -Wall -Wextra -Werror -std=c11 -pedantic
LIBS	= -lcrypto -lgdi32

all:
	$(RC) -i rsrc.rc -o rsrc.o
	$(CC) $(CFLAGS) minitowif.c rsrc.o $(LIBS) -o minitowif

clean:
	del *.exe
	del *.o