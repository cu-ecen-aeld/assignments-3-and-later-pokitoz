CC?=
CFLAGS = -Wall -Werror -g
default: all
all:
	$(CROSS_COMPILE)$(CC) -o aesdsocket aesdsocket.c $(CFLAGS)

clean:
	rm -f aesdsocket
	rm -f /var/tmp/aesdsocketdata

PHONY += all default clean