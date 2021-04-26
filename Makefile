CC	= gcc
CFLAGS	= -Wall -Wextra -g
LDFLAGS	= -pthread

.PHONY: all
all: client server

client: chatClient.o
	${CC} ${CFLAGS} ${LDFLAGS} -o $@ $^
server: chatServer.o
	${CC} ${CFLAGS} ${LDFLAGS} -o $@ $^
	
.PHONY clean:
clean: 
	rm client server chatClient.o chatServer.o