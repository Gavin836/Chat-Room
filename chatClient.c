#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <threads.h>
#include <unistd.h>
#include <fcntl.h>

#define BUF_LEN 2048
#define true 0
#define false 1

int sock_recv (void *sockfd_);
int sock_send (void *sockfd_);

// Globals
int end_client;

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
    
    // Set global program status
    end_client = false;
    // Using threads blocking issue
    thrd_t recv_thread;
    thrd_t send_thread;

    thrd_create(&send_thread, sock_send, (void *) &sock);
    thrd_create(&recv_thread, sock_recv, (void *) &sock);

    while (end_client == false) {
        usleep(100000);
    }
    
    // Close the sockets
    close(sock);

    // Clean up the threads.
    int retval;
    thrd_join(send_thread, &retval);
    thrd_join(recv_thread, &retval);

    // close the socket
    close(sock);
    return 0;
}

int sock_send (void *sockfd_) {
    int sockfd = *((int *)sockfd_);
    char data_to_send[BUF_LEN];
    
    while (1) {
        // Delay to prevent fgets from blocking sock_recv
        usleep(100000);
        fgets(data_to_send, BUF_LEN, stdin);
            
        //fgets reads in the newline character in buffer, get rid of it
        strtok(data_to_send,"\n");
        
        //actual send call for TCP socket
        send(sockfd, data_to_send, strlen(data_to_send) + 1, 0);
        
        if(strcmp(data_to_send, "OUT") == 0) break;

        // Reset buffers
        memset(data_to_send, 0, BUF_LEN);
    }
    
    return 0;
}

int sock_recv (void *sockfd_) {
    int sockfd = *((int *)sockfd_);
    char buffer[BUF_LEN];
    char *pbuf;
    
    while(recv(sockfd, buffer, BUF_LEN, 0) != 0) {
        fputs(buffer, stdout);
        
        if (strcmp("Goodbye!", buffer) == 0) {
            end_client = true;
        }
        
        // Print out rest of string, if buffer is delimited by '\0' 
        pbuf = buffer;
        pbuf += (strlen(buffer) + 1);
        while ((strlen(pbuf)) != 0) {
            fputs(pbuf, stdout);
            pbuf += (strlen(pbuf) + 1);
        }
        
        memset(buffer, 0, BUF_LEN);
    }
    
    return 0;
}