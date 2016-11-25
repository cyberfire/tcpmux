
CC=gcc
CFLAGS=-g  -Wall  -Werror -I../ -I.

COMMON_SRCS=../mux_log.c
COMMON_OBJS=$(COMMON_SRCS:.c=.o)


EXE_SRCS=echo_srv.c sample_extern_ident.c sample_proxy.c tcp_proxy.c access_control.c

EXE_OBJS=$(EXE_SRCS:.c=.o)
EXE_BINS=$(EXE_OBJS:.o=)


XMODULE_SRC=sample_xmodule.c
XMODULE_SO=$(XMODULE_SRC:.c=.so)


default: $(EXE_BINS) $(XMODULE_SO)

$(EXE_BINS): $(EXE_OBJS) 

access_control: $(COMMON_OBJS)


access_control:access_control.o
	$(CC) -o $@ $< $(COMMON_OBJS)


%.so:%.c
	$(CC) $(CFLAGS) -fPIC -shared -o $@ $<

%.o:%.c
	$(CC) $(CFLAGS) -c $< -o $@

%:%.o
	$(CC) -o $@ $< 

clean:
	rm -rf *.o *.so $(EXE_BINS)
