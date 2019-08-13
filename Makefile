LDFLAGS +=
CFLAGS += -Wall --std=gnu99

#-lcrypto must follow -lssl
OBJ := simplehttpd.o http_parser.o
LIB := -Wl,--export-dynamic -L/lib/i386-linux-gnu/ -ldl 

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

all: $(OBJ)
	$(CC) -o uhttpd $(LDFLAGS) $(LIB) $(OBJ)

clean:
	rm -f *.o *.so uhttpd

romfs:
	@echo "uhttpd romfs"
