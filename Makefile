CC = gcc
CFLAGS = -g -O2 -Wall
LDLIBS = -lpthread -ldl -lbfd -liberty

LIBTOOL = libtool --silent
INSTALL = install

PREFIX = /usr

NAME = bleak

all: lib$(NAME).la printleaks threadtest

%.lo: %.c
	$(LIBTOOL) --mode=compile $(CC) $(CFLAGS) -c $<

lib$(NAME).la: $(NAME).lo
	$(LIBTOOL) --mode=link $(CC) $(CFLAGS) -o $@ $< $(LDFLAGS) $(LDLIBS) -rpath /usr/lib

printleaks: printleaks.lo
	$(LIBTOOL) --mode=link $(CC) $(CFLAGS) -o $@ $< $(LDFLAGS) $(LDLIBS) lib$(NAME).la

threadtest: threadtest.lo
	$(LIBTOOL) --mode=link $(CC) $(CFLAGS) -o $@ $< $(LDFLAGS) $(LDLIBS) lib$(NAME).la

install: lib$(NAME).la
	$(INSTALL) -d $(DESTDIR)$(PREFIX)/lib
	$(LIBTOOL) --mode=install $(INSTALL) -s lib$(NAME).la $(DESTDIR)$(PREFIX)/lib/lib$(NAME).la

clean:
	rm -rf .libs lib$(NAME).la $(NAME).lo $(NAME).o \
		printleaks printleaks.lo printleaks.o \
		threadtest threadtest.lo threadtest.o \
		$(NAME).tgz

dist:
	rm -f $(NAME).tgz
	mkdir -p tmp/$(NAME)
	cp Makefile README LICENSE $(NAME).1 *.c tmp/$(NAME)
	cd tmp && tar zcf ../$(NAME).tgz $(NAME)
	rm -rf tmp
