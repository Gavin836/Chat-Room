#define SERVER_IP "127.0.0.1"
#define UPDATE_INTERVAL 1

#define BUF_LEN 2048

#define CRED_PATH "credentials.txt"
#define MSG_PATH "messagelog.txt"
#define USER_LOG "userlog.txt"

#define MAX_ARGS 4

#define MSG 0
#define DLT 1
#define EDT 2
#define RDM 3
#define ATU 4
#define OUT 5
#define UPD 6

typedef struct args *Args;

// Handlers for the sending and receiving threads.
int recv_handler(void *info);
int send_handler(void *info);

// Arguments struct (and creation function) to pass the required info
// into the thread handlers.
struct args {
    int fd;
};

////////////////////////////////////////////////////////////////////////
// Socket helper functions

// Get the "name" (IP address) of who we're communicating with.
char *get_name(struct sockaddr_in *sa, char *name);

// Populate a sockaddr_in struct with the specified IP / port to connect to.
void fill_sockaddr(struct sockaddr_in *sa, char *ip, int port);

// Get a string containing the current date/time.
char *get_time(void);

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
    int message_id;
    char *time;
    char *from;
    char *contents;
    int modified;
    struct chat_msg *next_msg;
};

// Connection handlers
int connect_handler(void *sockfd);
int authenticate (int sockfd, int no_attempts, char** ret);
int command_handler(int sockfd, struct active_user *curr_user);

// Send and recv wrappers
int recvtcp_to (int sockfd, char *buf);
int sendtcp_to (int sockfd, char *buf);

// Authentication list helpers
int insert_auth_list(char *username, char *password);

// User list helpers
struct active_user *create_active_user(char *username, char* ip, int port);
int user_list_insert(struct active_user *new_user);
void user_list_delete(struct active_user *user);
void active_user_destroy(struct active_user *user);

char **tokenise_args (char *input_string);