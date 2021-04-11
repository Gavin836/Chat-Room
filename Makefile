CC	= gcc
CFLAGS	= -Wall -Wextra -g
LDFLAGS	= -pthread

.PHONY: all
all: client server

client: cheddarClient.o
	${CC} ${CFLAGS} ${LDFLAGS} -o $@ $^
server: cheddarServer.o
	${CC} ${CFLAGS} ${LDFLAGS} -o $@ $^
	
.PHONY clean:
clean: 
	rm client server cheddarClient.o cheddarServer.o