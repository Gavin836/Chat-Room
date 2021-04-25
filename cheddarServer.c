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

/*

A good reference for C sockets programming (esp. structs and syscalls):
https://beej.us/guide/bgnet/html/multi/index.html

And for information on C Threads:
https://www.gnu.org/software/libc/manual/html_node/ISO-C-Threads.html

One of the main structs used in this program is the "sockaddr_in" struct.
See: https://beej.us/guide/bgnet/html/multi/ipstructsdata.html#structs

struct sockaddr_in {
    short int          sin_family;  // Address family, AF_INET
    unsigned short int sin_port;    // Port number
    struct in_addr     sin_addr;    // Internet address
    unsigned char      sin_zero[8]; // Same size as struct sockaddr
};

*/

#define SERVER_IP "127.0.0.1"
#define UPDATE_INTERVAL 1

#define BUF_LEN 2048

#define TRUE 0
#define FALSE 1

#define CRED_PATH "credentials.txt"
#define MSG_PATH "messagelog.txt"

typedef struct client_list *List;
typedef struct args *Args;

// Handlers for the sending and receiving threads.
int recv_handler(void *info);
int send_handler(void *info);

// Arguments struct (and creation function) to pass the required info
// into the thread handlers.
struct args {
    List list;
    int fd;
};

Args new_args(List list, int fd);


////////////////////////////////////////////////////////////////////////
// Socket helper functions

// Wrapper for the recv function, to avoid code duplication.
int recv_wrapper(int fd, char *buf, struct sockaddr_in *sockaddr_from,
        socklen_t *from_len, char *who);

// Wrapper for the sendto function, to avoid code duplication.
int send_wrapper(int fd, char *buf, struct sockaddr_in *sockaddr_to,
        socklen_t *to_len, char *who);

// Get a client_info struct based on the sockaddr we're communicating with.
struct client_info get_client_info(struct sockaddr_in *sa);

// Get the "name" (IP address) of who we're communicating with.
char *get_name(struct sockaddr_in *sa, char *name);

// Populate a sockaddr_in struct with the specified IP / port to connect to.
void fill_sockaddr(struct sockaddr_in *sa, char *ip, int port);

// "Print" out a client, by copying its host/port into the specified buffer.
char *print_client_buf(struct client_info client, char *buf);

// Compare two clients to see whether they have the same host/port.
int clients_equal(struct client_info a, struct client_info b);

// A wrapper function for fgets, similar to Python's built-in 'input' function.
void get_input(char *buf, char *msg);

// Get a string containing the current date/time.
char *get_time(void);
////////////////////////////////////////////////////////////////////////



////////////////////////////////////////////////////////////////////////
// List ADT
typedef struct client_node *Node;

struct client_list {
    Node head, tail;
    cnd_t t_lock;
    mtx_t mutex;
};

struct client_info {
    char host[INET_ADDRSTRLEN];
    int port;
};

struct client_node {
    struct client_info client;
    Node next, prev;
};

List list_new(void);
void list_add_node(List list, Node node);
void list_add(List list, struct client_info client);
void list_remove_client(List list, struct client_info client);
void list_remove(List list, Node to_remove);
bool list_contains(List list, struct client_info client);
Node list_find(List list, struct client_info client);
void list_destroy(List list);
void print_list(List list);

Node node_new(struct client_info client);
void node_destroy(Node node);
////////////////////////////////////////////////////////////////////////
// Data structures
 struct auth_ent {
    char *username;
    char *password;
    int failed_login;
    struct auth_ent *next_ent;
};

struct active_user {
    char *username;
    char *time;
    char *ip;
    int udp_port;
    struct active_user *next_user;
};

struct chat_msg {
    int message_no;
    int time;
    char *from;
    char *to;
    char *contents;
    int modified;
    struct chat_msg *next_msg;
};

// Globals
struct auth_ent *auth_head;
struct active_user *user_head;
struct chat_msg *msg_head;

// Connection handlers
int connect_handler(void *sockfd);
int authenticate (int sockfd, int no_attempts, char** ret);
int command_handler(int sockfd, struct active_user *curr_user);

struct active_user *create_active_user(char *username, char* ip, int port);
int user_list_insert(struct active_user *new_user);
void user_list_delete(struct active_user *user);
void active_user_destroy(struct active_user *user);

int recvtcp_to (int sockfd, char *buf);
int sendtcp_to (int sockfd, char *buf);

// Authentication list helpers
int insert_auth_list(char *username, char *password);

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
    char cmd[4];
    
    (void) curr_user;
    
    while (1) {
        sendtcp_to(sockfd, "Please enter a command: ");
        recvtcp_to(sockfd, recv_buf);
        
        strncpy(cmd, recv_buf, 3);
                
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

















int recv_handler(void *args_) {
    Args args = (Args) args_;
    List list = args->list;
    int server_fd = args->fd;

    // Array that we'll use to store the data we're sending / receiving.
    char buf[BUF_LEN + 1] = {0};

    // Create the sockaddr that the server will use to receive data from
    // the client (and to then send data back).
    struct sockaddr_in sockaddr_from;

    // We need to create a variable to store the length of the sockaddr
    // we're using here, which the recvfrom function can update if it
    // stores a different amount of information in the sockaddr.
    socklen_t from_len = sizeof(sockaddr_from);

    while (1) {

        // The `recv_wrapper` function wraps the call to recv, to avoid
        // code duplication.
        recv_wrapper(server_fd, buf, &sockaddr_from, &from_len, "recv");

        // Create a struct with the information about the client
        // (host, port) -- similar to "clientAddress" in the Python.
        struct client_info client = get_client_info(&sockaddr_from);

        // THe `with t_lock:` in the python code is equivalent to
        // `t_lock.acquire()` -- it calls the `acquire` function to
        // lock the underlying lock.
        //
        // In C, the condition variable and the mutex are two separate
        // things to create and keep track of.
        //
        // To acquire the lock in C, we call `mtx_lock` on the mutex.

        // Get the lock.
        printf("[recv] Waiting on the mutex...\n");
        mtx_lock(&(list->mutex));
        printf("[recv] Locked the mutex!\n");

        printf("[recv] Received request from %s listening at %d: %s at time %s",
                client.host, client.port, buf, get_time());

        if (!strcmp(buf, "Subscribe")) {
            list_add(list, client);
            strcpy(buf, "Subscription successful");

        } else if (!strcmp(buf, "Unsubscribe")) {
            if (list_contains(list, client)) {
                list_remove_client(list, client);
                strcpy(buf, "Subscription removed");
            } else {
                strcpy(buf, "You are not currently subscribed");
            }

        } else {
            strcpy(buf, "Unknown command, send Subscribe or Unsubscribe only");
        }

        // The `send_wrapper` function wraps the call to sendto, to
        // avoid code duplication.
        send_wrapper(server_fd, buf, &sockaddr_from, &from_len, "recv");

        // Now that we're finished, we want to notify the waiting thread
        // and release the lock.

        // Wake up one waiting thread.
        // This is the equivalent of `t_lock.notify()` in the Python code:
        printf("[recv] signalling...\n");
        cnd_signal(&(list->t_lock));
        printf("[recv] signaled\n");

        // And unlock the mutex now that we're done.
        // This is the equivalent of the end of the `with t_lock:` block
        printf("[recv] unlocking the mutex...\n");
        mtx_unlock(&(list->mutex));
        printf("[recv] mutex unlocked!\n");
    }

    return EXIT_SUCCESS;
}

int send_handler(void *args_) {
    Args args = (Args) args_;
    List list = args->list;
    int client_fd = args->fd;

    // Array that we'll use to store the data we're sending / receiving.
    char buf[BUF_LEN + 1] = {0};

    // Temporary array used to store the name of the client when printing.
    char name[BUF_LEN] = {0};

    while (1) {

        // Get the lock.
        printf("[send] Waiting on the mutex...\n");
        mtx_lock(&(list->mutex));
        printf("[send] Locked the mutex!\n");

        print_list(list);

        // For each client:
        for (Node curr = list->head; curr != NULL; curr = curr->next) {

            // Get the current time.
            char *curr_time = get_time();
            snprintf(buf, BUF_LEN, "Current time is %s", curr_time);

            printf("[send] Curr client is: %s\n",
                    print_client_buf(curr->client, name));


            // We create a sockaddr_in to store the details of the
            // client we're replying to, and fill it with the client's
            // host/port from the client_info struct.
            struct sockaddr_in sockaddr_to = {0};
            socklen_t to_len = sizeof(sockaddr_to);
            fill_sockaddr(&sockaddr_to, curr->client.host, curr->client.port);

            printf("[send] Sending time to %s listening at %d at time %s\n",
                    curr->client.host, curr->client.port, curr_time);

            send_wrapper(client_fd, buf, &sockaddr_to, &to_len, "send");
        }

        // Wake up one waiting thread.
        // This is the equivalent of `t_lock.notify()` in the Python code:
        printf("[send] signalling...\n");
        cnd_signal(&(list->t_lock));
        printf("[send] signaled\n");

        // And unlock the mutex now that we're done.
        // This is the equivalent of the end of the `with t_lock:` block
        printf("[send] unlocking the mutex...\n");
        mtx_unlock(&(list->mutex));
        printf("[send] mutex unlocked!\n");

        // sleep for UPDATE_INTERVAL
        printf("[send] sleeping...\n");
        sleep(UPDATE_INTERVAL);

    }
    return EXIT_SUCCESS;
}



////////////////////////////////////////////////////////////////////////
// Wrappers for sendto and recv

// A wrapper for the recvfrom function.
// The `who` parameter will be "send" or "recv", to make the output
// clearer (so that you can see which thread called the function).
int recv_wrapper(int fd, char *buf, struct sockaddr_in *sockaddr_from,
        socklen_t *from_len, char *who) {

    char name[BUF_LEN] = {0};

    printf("[%s] Receiving...\n", who);
    int numbytes = recvfrom(fd, buf, BUF_LEN, 0,
        (struct sockaddr *) sockaddr_from, from_len);

    buf[numbytes] = '\0';
    buf[strcspn(buf, "\n")] = '\0';

    struct client_info client = get_client_info(sockaddr_from);

    printf("[%s] Received %d bytes from %s: %s\n", who, numbytes,
            print_client_buf(client, name), buf);

    return numbytes;
}

// A wrapper for the sendto function.
// The `who` parameter will be "send" or "recv", to make the output
// clearer (so that you can see which thread called the function).
int send_wrapper(int fd, char *buf, struct sockaddr_in *sockaddr_to,
        socklen_t *to_len, char *who) {

    char name[BUF_LEN] = {0};

    int numbytes = sendto(fd, buf, strlen(buf), 0,
            (struct sockaddr *) sockaddr_to, *to_len);

    struct client_info client = get_client_info(sockaddr_to);

    printf("[%s] Sent %d bytes to %s: %s\n", who, numbytes,
            print_client_buf(client, name), buf);

    return numbytes;

}
////////////////////////////////////////////////////////////////////////



////////////////////////////////////////////////////////////////////////
// Socket helper functions

Args new_args(List list, int fd) {
    Args args = calloc(1, sizeof(*args));
    args->list = list;
    args->fd = fd;
    return args;
}

// Wrapper function for fgets, similar to Python's built-in 'input'
// function.
void get_input (char *buf, char *msg) {
    printf("%s", msg);
    fgets(buf, BUF_LEN, stdin);
    buf[strcspn(buf, "\n")] = '\0'; // Remove the newline
}

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

// Populates a client_info struct from a `sockaddr_in`.
struct client_info get_client_info(struct sockaddr_in *sa) {
    struct client_info info = {};
    info.port = ntohs(sa->sin_port);
    inet_ntop(sa->sin_family, &(sa->sin_addr), info.host, INET_ADDRSTRLEN);

    return info;
}

// Get the "name" (IP address) of who we're communicating with.
// Takes in an array to store the name in.
// Returns a pointer to that array for convenience.
char *get_name(struct sockaddr_in *sa, char *name) {
    inet_ntop(sa->sin_family, &(sa->sin_addr), name, BUF_LEN);
    return name;
}

// Compare two client_info structs to see whether they're the same.
int clients_equal(struct client_info a, struct client_info b) {
    return (a.port == b.port && !strcmp(a.host, b.host));
}

// Get the current date/time.
char *get_time(void) {
    time_t t = time(0);
    return ctime(&t);
}
////////////////////////////////////////////////////////////////////////



////////////////////////////////////////////////////////////////////////
// List ADT

void print_client(struct client_info client) {
    printf("%s:%d\n", client.host, client.port);
}

char *print_client_buf(struct client_info client, char *buf) {
    sprintf(buf, "%s:%d", client.host, client.port);
    return buf;
}

void print_list(List list) {

    printf("---------------\n");
    printf("Clients are: \n");

    char name[BUF_LEN] = {0};
    for (Node curr = list->head; curr != NULL; curr = curr->next) {
        printf("%s -> ", print_client_buf(curr->client, name));
    }

    printf("X\n");

    printf("---------------\n");

}

List list_new(void) {
    List list = calloc(1, sizeof(*list));

    // It would be a good idea to check the return value of these inits,
    // to make sure that they succeeded.
    cnd_init(&list->t_lock);
    mtx_init(&list->mutex, mtx_plain);

    return list;
}

void list_add(List list, struct client_info client) {
    printf("Adding a client: "); print_client(client);
    Node new = node_new(client);
    list_add_node(list, new);
}

void list_add_node(List list, Node node) {
    assert(list != NULL);

    if (list->tail == NULL) {
        assert(list->head == NULL);
        list->head = list->tail = node;
    } else {
        assert(list->head != NULL);
        list->tail->next = node;
        node->prev = list->tail;
        list->tail = node;
    }
}

void list_remove_client(List list, struct client_info client) {
    printf("Removing a client: "); print_client(client);

    Node to_remove = list_find(list, client);
    list_remove(list, to_remove);
}

void list_remove(List list, Node to_remove) {

    if (to_remove == NULL) {
        fprintf(stderr, "Tried to remove a node that wasn't in the list!");
        return;
    }

    if (list->head == to_remove) {
        assert(to_remove->prev == NULL);
        list->head = to_remove->next;
    }

    if (list->tail == to_remove) {
        assert(to_remove->next == NULL);
        list->tail = to_remove->prev;
    }

    if (to_remove->next) to_remove->next = to_remove->next->next;
    if (to_remove->prev) to_remove->prev = to_remove->prev->prev;

    node_destroy(to_remove);

}

bool list_contains(List list, struct client_info client) {
    assert(list != NULL);

    return (list_find(list, client) != NULL);
}

// Returns the node, or NULL if not found.
Node list_find(List list, struct client_info client) {
    assert(list != NULL);

    Node found = NULL;
    for (Node curr = list->head; curr != NULL; curr = curr->next) {
        if (clients_equal(curr->client, client)) found = curr;
    }
    return found;
}

void list_destroy(List list) {
    for (Node curr = list->head; curr != NULL;) {
        Node tmp = curr;
        curr = curr->next;
        node_destroy(tmp);
    }

    mtx_destroy(&list->mutex);
    cnd_destroy(&list->t_lock);

    free(list);
}

Node node_new(struct client_info client) {
    Node node = calloc(1, sizeof(*node));
    node->client = client;
    return node;
}

void node_destroy(Node node) {
    free(node);
}

////////////////////////////////////////////////////////////////////////
