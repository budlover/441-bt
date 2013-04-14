# Some variables
CC 		= gcc
CFLAGS		= -g  -Wall  -DDEBUG -Werror
LDFLAGS		= -lm
TESTDEFS	= -DTESTING			# comment this out to disable debugging code
OBJS		= peer.o bt_parse.o spiffy.o input_buffer.o chunk.o sha.o\
              ht.o bt_protocol.o str_helper.o config.o sel_ctrl.o req.o\
              bt_info.o dbg_helper.o darr.o pkts.o peer_info.o winsz_logger.o

MK_CHUNK_OBJS   = make_chunks.o chunk.o sha.o

BINS            = peer make-chunks
#TESTBINS        = test_debug test_input_buffer

# Implicit .o target
.c.o:
	$(CC) $(TESTDEFS) -c $(CFLAGS) $<

# Explit build and testing targets

all: ${BINS} ${TESTBINS}

run: peer_run
	./peer_run

test: peer_test
	./peer_test

peer: $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o $@ $(LDFLAGS)

make-chunks: $(MK_CHUNK_OBJS)
	$(CC) $(CFLAGS) $(MK_CHUNK_OBJS) -o $@ $(LDFLAGS)

clean:
	rm -f *.o $(BINS) $(TESTBINS)

bt_parse.c: bt_parse.h

# The debugging utility code

test_input_buffer:  test_input_buffer.o input_buffer.o
