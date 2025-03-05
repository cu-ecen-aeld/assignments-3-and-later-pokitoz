CROSS_COMPILE ?= aarch64-linux-gnu-
CFLAGS = -Wall -Werror -g
default: all
all:
	$(CROSS_COMPILE)gcc -o aesdsocket aesdsocket.c $(CFLAGS)

clean:
	rm -f aesdsocket
	rm -f /var/tmp/aesdsocketdata

PHONY += all default clean