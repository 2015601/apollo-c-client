# example makefile

CC ?= gcc

OBJS := client.o
CFLAGS := -g3 -o0 -Wall -Werror
# CFLAGS += -fsanitize=address -fno-omit-frame-pointer
LDFLAGS := -lapollo -lcjson #-lasan

.PHONY: clean client apollo

client: $(OBJS)
	$(CC) -o $@ $(OBJS) $(LDFLAGS)

.c.o:
	$(CC) -c $(CFLAGS) -o $@ $<

apollo:
	make -C ../ clean
	make -C ../ uninstall
	make -C ../ install

clean:
	rm -f *.o
	rm -f client
