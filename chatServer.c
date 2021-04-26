// Sample network sockets code - UDP Server.
// Written for COMP3331 by Andrew Bennett, October 2019.

#include <arpa/inet.h>
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <threads.h>
#include <unistd.h>

#include "chatServer.h"

// Globals
struct auth_ent *auth_head;
struct active_user *user_head;
struct chat_msg *msg_head;

// Used to load data before server runs
int bootstrap (void){
    FILE *fd_cred;
    char read_buffer[BUF_LEN];
    char *username;
    char *password;
    
    // Extract credentials from file
    fd_cred = fopen(CRED_PATH, "r");
    
    if (fd_cred != NULL) {
        while(fgets(read_buffer, BUF_LEN, fd_cred) != NULL) {
            // Username and passwords are delimited by a " " character
            username = strtok(read_buffer, " ");
            password = strtok(NULL, " ");
            insert_auth_list(username, password);
        }
    }
    
    // fclose(fd_cred);
    return 0;
}

int main(int argc, char *argv[]) {
    // Set port number and failed attempt number from arguments
    if (argc != 3) {
        printf("Invalid number of arguments");
        return 1;
    }
    
    int SERVER_PORT = atoi(argv[1]);
    int NUM_FAILED_ATTEMPTS = atoi(argv[2]);
    
    (void) NUM_FAILED_ATTEMPTS;
    
    // Create the server's socket.
    //
    // The first parameter indicates the address family; in particular,
    // `AF_INET` indicates that the underlying network is using IPv4.
    //
    // The second parameter indicates that the socket is of type
    // SOCK_STREAM, which means it is a TCP socket 
    
    // This returns a file descriptor, which we'll use with our sendto /
    // recvfrom functions later.
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    // int client_fd = socket(AF_INET, SOCK_STREAM, 0);

    // Create the sockaddr that the server will use to send data to the
    // client.
    struct sockaddr_in sockaddr_to;
    fill_sockaddr(&sockaddr_to, SERVER_IP, SERVER_PORT);

    // Let the server reuse the port if it was recently closed and is
    // now in TIME_WAIT mode.
    const int so_reuseaddr = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &so_reuseaddr, sizeof(int));

    printf("Binding...\n");
    if (bind(server_fd, (struct sockaddr *) &sockaddr_to, 
             sizeof(sockaddr_to)) < 0){
        printf("Failed to bind");
        return 1;
    }
    
    printf("Listening...\n");
    int wait_size = 5;  // maximum number of waiting clients
    if (listen(server_fd, wait_size) < 0) {
        printf("Could not open socket for listening\n");
        return 1;
    }
    
    // Initialise credentials
    bootstrap();
    
    // Dispatch the sockfd to a handler thread
    int newfd;
    struct sockaddr_storage their_addr;
    socklen_t their_size = sizeof(their_addr);
    thrd_t request_handler;
    while((newfd = accept(server_fd, (struct sockaddr *)&their_addr, 
                          &their_size)) != -1) {
        printf("accepting ...\n");
        if (newfd < 0) {
            printf("Failed to open socket on accept");
            break;
        }
        
        fputs("creating thread\n", stdout);
        thrd_create(&request_handler, connect_handler, (void *) &newfd);
    }

    return 0;
}

int connect_handler(void *sockfd_) {
    int sockfd = *((int *) sockfd_);   
    int auth_passed;
    char *username;
    // Authenticate user with n attempts
    username = calloc(BUF_LEN, sizeof(char));
    if (username == NULL) {
        return 1;
    }
    
    auth_passed = authenticate(sockfd, 3, &username); 
    if (auth_passed != true) {
        sendtcp_to(sockfd, "Failed to create user");
    }
    
    struct active_user *curr_user =  create_active_user(username, "Ip", 1);
    sendtcp_to(sockfd, "Log in sucess!\n");
    command_handler(sockfd, curr_user);
    
    user_list_delete(curr_user);
    free(username);
    close(sockfd);
    return 0;
}

int command_handler(int sockfd, struct active_user *curr_user) {
    char recv_buf[BUF_LEN];
    char **recv_args;
    char cmd[4];
    char *args;
    
    (void) curr_user;
    
    while (1) {
        sendtcp_to(sockfd, "Please enter a command: ");
        recvtcp_to(sockfd, recv_buf);
        
        args = recv_buf + 3;
        recv_args = tokenise_args(args);                
        
        if (strcmp("MSG", cmd) == 0) {

        } else if (strcmp("DLT", cmd) == 0) {
        
        } else if (strcmp("EDT", cmd)  == 0) {
        
        } else if (strcmp("RDM", cmd) == 0) {
        
        } else if (strcmp("ATU", cmd) == 0) {
        
        } else if (strcmp("OUT", cmd) == 0) {
            sendtcp_to(sockfd, "Goodbye! Signed out\n");
            break;
        
        } else {
            sendtcp_to(sockfd, "Invalid Command.");
            continue;
        }
        
        sendtcp_to(sockfd, "Please enter a command: ");
    }
    
    return 0;
}

int cmd_msg (int sockfd, char** args, struct active_user *sender) {
    char *msg;
    struct chat_msg *new_msg;
    
    msg = args[0];
    // Check arguments are valid
    if (msg == NULL || (strlen(msg) < 1) ) {
        sendtcp_to(sockfd, "No message argument for MSG\n");
        return 0;
    }
    
    new_msg = calloc(1, sizeof(struct chat_msg));
    
    if (msg == NULL) return 1;
    
    new_msg->contents = strdup(msg);
    if (new_msg->contents == NULL) {
        free(new_msg);
        return 1;
    }
    
    new_msg->from = sender->username;
    new_msg->modified = false;
    new_msg->time = get_time();

}

char **tokenise_args (char *input_string) {
    char **args;
    char *cur_string;
    int i;
    
    args = calloc(MAX_ARGS, sizeof(char *));
    cur_string = strtok(input_string, " ");
    
    for (i = 0; i < MAX_ARGS; i++) {
        if(cur_string == NULL) break;
        args[i] = strdup(cur_string);
        
        cur_string = strtok(NULL, " ");
    }
    
    return args;
}

struct active_user *create_active_user(char *username, char* ip, int port) {
    struct active_user *new_user;
    int result;
    
    new_user = calloc(1, sizeof(struct active_user));
    
    if (new_user == NULL) {
        return NULL;
    }
    
    new_user->username = strdup(username);
    new_user->time = get_time();
    new_user->ip = strdup(ip);
    new_user->udp_port = port;
    new_user->next_user = NULL;
    
    result = user_list_insert(new_user);
    
    if (result != 0) {
        free(new_user);
        return NULL;
    }    
    
    return new_user;
}

int user_list_insert(struct active_user *new_user) {
    
    if (user_head == NULL) user_head = new_user;
    
    new_user->next_user = user_head;
    user_head = new_user;
    
    return 0;
}

void user_list_delete(struct active_user *user) {
    struct active_user *prev;
    struct active_user *curr_user;
    
    prev = NULL;
    curr_user = user_head;
    
    if (curr_user == user) {
        if (prev == NULL) {
            user_head = user->next_user;
        } else {
            prev->next_user = user->next_user;
        }
    }
    active_user_destroy(user);
}

void active_user_destroy(struct active_user *user) {
    free(user->username);
    free(user->ip);
    free(user);
}

int authenticate (int sockfd, int no_attempts, char** ret) {
    char *buf;
    char send_buf[BUF_LEN];
    char username[BUF_LEN];
    char password[BUF_LEN];
    FILE *fd;
    struct auth_ent *curr_ent;
        
    sendtcp_to(sockfd, "Username: ");
    while (1) {
        // Recv for Username
        recvtcp_to(sockfd, username);
        
        sendtcp_to(sockfd, "Password: ");
        recvtcp_to(sockfd, password);
        
        // Check credentials
        if (auth_head != NULL) {
            curr_ent = auth_head;
            while (curr_ent != NULL ) {
                if (strcmp(username, curr_ent->username) == 0) {
                    if (strcmp(password, curr_ent->password) == 0) {
                        curr_ent->failed_login = 0;
                        strcpy(*ret, username);
                        return true;
                    }
                    
                    curr_ent->failed_login++;
                    break;
                }
                curr_ent = curr_ent->next_ent;
            }
        }
        
        // New Login created when auth list is empty/ no entry found.
        // Return true if entry added.
        if (auth_head == NULL || curr_ent == NULL) {
            if (insert_auth_list(username, password) == 0) {
                // Write into credentials file
                fd = fopen(CRED_PATH, "a");
                buf = calloc(BUF_LEN, sizeof(char));
                strcpy(buf, username);
                strcat(buf, " ");
                strcat(buf, password);
                
                fputs(buf, fd);
                free(buf);
                strcpy(*ret, username);
                return true;
            }
            
            return false;
        }
        
        // Failed login logic
        if (curr_ent->failed_login != no_attempts) {
            snprintf(send_buf, BUF_LEN, "Failed login %d of %d \nUsername: ",
                     curr_ent->failed_login , no_attempts);
            sendtcp_to(sockfd, send_buf);
        
        } else {
            sendtcp_to(sockfd, "Authentication failed. Waiting 10 secs before input is accepted\nUsername: ");
            curr_ent->failed_login = 0;
            usleep(10000000);
        }

        // Reset buffers
        memset(send_buf, 0, BUF_LEN);
        memset(username, 0, BUF_LEN);
        memset(password, 0, BUF_LEN);
    }
    
    return false;
}

int insert_auth_list(char *username, char *password) {
    struct auth_ent *new_auth; 

    new_auth = calloc(1, sizeof(struct auth_ent *));
    new_auth->username = calloc(BUF_LEN, sizeof(char));
    if(new_auth->username == NULL) return 1;
    
    new_auth->password = calloc(BUF_LEN, sizeof(char));
    if(new_auth->password == NULL) {
        free(new_auth->username);
        return 1;
    }
    
    new_auth->failed_login = 0;
    new_auth->next_ent = NULL;
       
    strcpy(new_auth->username, username);
    strcpy(new_auth->password, password);
    
    // Insert node linked list
    if (auth_head == NULL) {
        auth_head = new_auth;
    } else {
        new_auth->next_ent = auth_head;
        auth_head = new_auth;
    }
    
    return 0;
}

/* Wrappers for send and recv */

int recvtcp_to (int sockfd, char *buf) {
    int bytes_recv;
    char recv_buf[BUF_LEN];
    
    bytes_recv = recv(sockfd, recv_buf, BUF_LEN, 0);
    
    if (bytes_recv < 1) return 0;

    strcpy(buf, recv_buf);
    
    return strlen(buf);
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
    
    return 0;
}


/* Socket helpers */

// Populate a `sockaddr_in` struct with the IP / port to connect to.
void fill_sockaddr(struct sockaddr_in *sa, char *ip, int port) {

    // Set all of the memory in the sockaddr to 0.
    memset(sa, 0, sizeof(struct sockaddr_in));

    // IPv4.
    sa->sin_family = AF_INET;

    // We need to call `htons` (host to network short) to convert the
    // number from the "host" endianness (most likely little endian) to
    // big endian, also known as "network byte order".
    sa->sin_port = htons(port);
    sa->sin_addr.s_addr = htonl(INADDR_ANY);
    inet_pton(AF_INET, ip, &(sa->sin_addr));
}

// Get the "name" (IP address) of who we're communicating with.
// Takes in an array to store the name in.
// Returns a pointer to that array for convenience.
char *get_name(struct sockaddr_in *sa, char *name) {
    inet_ntop(sa->sin_family, &(sa->sin_addr), name, BUF_LEN);
    return name;
}

// Get the current date/time.
char *get_time(void) {
    time_t t = time(0);
    return ctime(&t);
}
////////////////////////////////////////////////////////////////////////