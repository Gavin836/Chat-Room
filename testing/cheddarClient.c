#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <threads.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <assert.h>


#define BUF_LEN 2048
#define true 0
#define false 1

int recvtcp_to (int sockfd, char *buf);
int sendtcp_to (int sockfd, char *buf);

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

    int len = 0;
    char buffer[BUF_LEN];
    char data_to_send[BUF_LEN];
    int recv_num = 0;
    while (1) {
        // Server reply block until received
        puts("recv");
        len = recvtcp_to(sock, buffer);
        puts("passed")
        printf("%s\n", buffer);
        assert(len > 0);
        
        recv_num = atoi(buffer);
        assert(recv_num > 0);
        
        for (int i = 0; i < recv_num ; i++) {
            len = recvtcp_to(sock, buffer);
            assert(len > 0);

            buffer[len] = '\0';
            printf("%s", buffer);

        }
        
        // Client response
        fgets(data_to_send, BUF_LEN, stdin);
        //fgets reads in the newline character in buffer, get rid of it
        strtok(data_to_send,"\n");
        //actual send call for TCP socket
        int bytes_sent = sendtcp_to(sock, data_to_send);
        assert(bytes_sent > 0);
        // Reset buffers
        memset(buffer, 0, BUF_LEN);
        memset(data_to_send, 0, BUF_LEN);
    }

    // close the socket
    close(sock);
    return 0;
}

int recvtcp_to (int sockfd, char *ret) {
    int n = 0;
    int len = 0, maxlen = 100;
    char buffer[maxlen];
    char *pbuffer = buffer;
    while ((n = recv(sockfd, pbuffer, maxlen, 0)) > 0) {
        pbuffer += n;
        maxlen -= n;
        len += n;
     
    }
    strcpy(ret, buffer);
    return len;
            
    // int bytes_recv;
    // char recv_buf[BUF_LEN];
    
    // bytes_recv = recv(sockfd, recv_buf, BUF_LEN, 0);
    
    // if (bytes_recv < 1) return 0;

    // strcpy(buf, recv_buf);
    
    // return bytes_recv;
}

int sendtcp_to (int sockfd, char *buf) {
    char send_buf[BUF_LEN];
    char *psend_buf;
    int bytes_sent, bytes_remaining;
    
    strcpy(send_buf, buf);
    psend_buf = send_buf;
    bytes_sent = 0;    
    bytes_remaining = strlen(buf);
    
    while(bytes_remaining > 0) {
        bytes_sent = send(sockfd, psend_buf, strlen(psend_buf) + 1, 0);
        bytes_remaining -= bytes_sent;
        psend_buf += bytes_sent;
    }
    
    return bytes_sent;
}