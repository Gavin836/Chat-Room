#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

#define BUF_LEN 2048

int main(int argc, char *argv[]) {
    // From argument get server ip and port, and udp port
    if (argc != 4) {
        printf("Invalid arguments: ./client server_ip server_port udp_port");
    }
    char * server_name = argv[1];
    int server_port = atoi(argv[2]);
    int udp_port = atoi(argv[3]);
    (void) udp_port;
    
    //this struct will contain address + port No
    struct sockaddr_in server_address;
    memset(&server_address, 0, sizeof(server_address));
    server_address.sin_family = AF_INET;
    
    // http://beej.us/guide/bgnet/output/html/multipage/inet_ntopman.html
    inet_pton(AF_INET, server_name, &server_address.sin_addr);
    
    // htons: port in network order format
    server_address.sin_port = htons(server_port);
    
    // open a TCP stream socket using SOCK_STREAM, verify if socket successfuly opened
    int sock;
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        printf("could not open socket\n");
        return 1;
    }
    
    // TCP is connection oriented, a reliable connection
    // **must** be established before any data is exchanged
    //initiate 3 way handshake
    //verify everything ok
    if (connect(sock, (struct sockaddr*)&server_address,
                sizeof(server_address)) < 0) {
        printf("could not connect to server\n");
        return 1;
    }
    
    // prepare to receive
    int len = 0, maxlen = 100;
    char buffer[maxlen];
    char* pbuffer = buffer;
    
    char data_to_send[BUF_LEN];
    
    while (1) {
        // Server reply block until received
        while ((len = recv(sock, pbuffer, maxlen, 0)) < 1);
        buffer[len] = '\0';
        printf("%s", buffer);
        
        // Close client reply
        if(strcmp(buffer, "Close") == 0) {
            break;
        }
        
        // Client response
        fgets(data_to_send, BUF_LEN, stdin);
        //fgets reads in the newline character in buffer, get rid of it
        strtok(data_to_send,"\n");
        printf("read : %s\n",data_to_send);
        //actual send call for TCP socket
        send(sock, data_to_send, strlen(data_to_send)+1, 0);
        
        // Reset buffers
        memset(buffer, 0, BUF_LEN);
        memset(data_to_send, 0, BUF_LEN);
    }

    // close the socket
    close(sock);
    return 0;
}
