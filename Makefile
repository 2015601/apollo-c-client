# apollo client makefile

CC ?= gcc
AR ?= ar
LDCONFIG ?= ldconfig

OBJS := apollo.o
CFLAGS := -fPIC -g -o0 -Wall -Werror

LIBVERSION = 1

STATIC_LIB = libapollo.a
SHARED_LIB = libapollo.so
SHARED_LIB_VERSION = $(SHARED_LIB).$(LIBVERSION)

PREFIX ?= /usr/local
INCLUDE_PATH ?= include/apollo
LIBRARY_PATH ?= lib

INSTALL_INCLUDE_PATH = $(DESTDIR)$(PREFIX)/$(INCLUDE_PATH)
INSTALL_LIBRARY_PATH = $(DESTDIR)$(PREFIX)/$(LIBRARY_PATH)
INSTALL ?= cp -a


.PHONY: apollo install clean uninstall

apollo: cjson $(OBJS) $(STATIC_LIB) $(SHARED_LIB_VERSION) $(SHARED_LIB)

install: $(STATIC_LIB) $(SHARED_LIB_VERSION) $(SHARED_LIB) apollo.h
	mkdir -p $(INSTALL_LIBRARY_PATH) $(INSTALL_INCLUDE_PATH)
	$(INSTALL) apollo.h $(INSTALL_INCLUDE_PATH)
	$(INSTALL) $(SHARED_LIB_VERSION) $(INSTALL_LIBRARY_PATH)
	$(INSTALL) $(SHARED_LIB) $(INSTALL_LIBRARY_PATH)
	$(INSTALL) $(STATIC_LIB) $(INSTALL_LIBRARY_PATH)
	$(LDCONFIG)


$(STATIC_LIB): $(OBJS)
	$(AR) crs $@ $^

$(SHARED_LIB_VERSION): $(OBJS)
	$(CC) -shared -o $@ $^ -Wl,-soname=$(SHARED_LIB_VERSION)

$(SHARED_LIB): $(SHARED_LIB_VERSION)
	ln -s $< $@

$(OBJS): %o: %c
	$(CC) -c $(CFLAGS) -o $@ $<

cjson:
	make -C cJSON
	make -C cJSON install

clean:
	rm -f *.o
	rm -f *.a
	rm -f *.so.*

uninstall:
	$(RM) $(INSTALL_LIBRARY_PATH)/$(SHARED_LIB)
	$(RM) $(INSTALL_LIBRARY_PATH)/$(SHARED_LIB_VERSION)
	$(RM) $(INSTALL_INCLUDE_PATH)/$(STATIC_LIB)
	$(RM) $(INSTALL_INCLUDE_PATH)/apollo.h
