
CC=gcc
CFLAGS=-g  -Wall  -Werror -I.

SAMPLE_SRCS=sample/sample_intern_ident.c
CFLAGS+=-I ./sample

COMMON_SRCS=config_parser.c proto_ident.c proto_server.c internal_ident.c xmodule.c mux_log.c proxy_server.c  $(SAMPLE_SRCS)

EXE_SRCS=tcpmux.c

COMMON_OBJS=$(COMMON_SRCS:.c=.o)
EXE_OBJS=$(EXE_SRCS:.c=.o)



EXE_BINS=$(EXE_OBJS:.o=)
LIBS=-lconfig -ldl

XMODULE=sample_xmodule.so

default: $(EXE_BINS) sample

$(EXE_BINS):  $(COMMON_OBJS)

$(EXE_BINS):%:%.o #rule to explicitly define EXE depends on EXE.o

.PHONY: sample

sample:
	$(MAKE) -C $@

#sample_xmodule.so:sample_xmodule.c

%.so:%.c
	$(CC) -fPIC -shared -o $@ $<

%.o:%.c
	$(CC) $(CFLAGS) -c $< -o $@

%:%.o
	$(CC) -rdynamic -o $@ $< $(COMMON_OBJS) $(LIBS)
	
	

clean:
	rm -rf *.o *.so $(EXE_BINS)
	$(MAKE) -C sample clean
