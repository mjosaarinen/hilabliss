# Makefile
# 09-Jun-15  Markku-Juhani O. Saarinen <mjos@iki.fi>

BIN	= hila
OBJS	= ntt32.o bliss.o bliss_param.o sha3.o main.o distribution.o \
	notrandom.o
DIST	= hilabliss

CC	= gcc
CFLAGS	= -Wall -Ofast 
LIBS	= -lm
LDFLAGS	=
INCS	=

$(BIN): $(OBJS)
	$(CC) $(LDFLAGS) -o $(BIN) $(OBJS) $(LIBS)

.c.o:
	$(CC) $(CFLAGS) $(INCS) -c $< -o $@

clean:
	rm -rf $(DIST)-*.txz $(OBJS) $(BIN) *~

dist:	clean
	cd ..; \
	tar cfvJ $(DIST)/$(DIST)-`date -u "+%Y%m%d%H%M00"`.txz $(DIST)/*
