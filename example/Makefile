# example makefile

CC ?= gcc

OBJS := main.o
CFLAGS := -g -o0 -Wall -Werror
LDFLAGS := -lapollo -lcjson

.PHONY: clean client

client: $(OBJS) apollo
	$(CC) -o $@ $(OBJS) $(LDFLAGS)

$(OBJS): %o: %c
	$(CC) -c $(CFLAGS) -o $@ $<

apollo:
	make -C ../ install

clean:
	rm -f *.o
	rm -f test
