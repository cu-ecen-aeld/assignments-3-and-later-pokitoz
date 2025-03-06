CC?=
CFLAGS = -Wall -Werror -g

TARGET_NAME = aesdsocket
default: all
all:
	$(CROSS_COMPILE)$(CC) -o $(TARGET_NAME) aesdsocket.c $(CFLAGS)

clean:
	rm -f $(TARGET_NAME)
	rm -f /var/tmp/aesdsocketdata

PHONY += all default clean
.PHONY: $(PHONY)
