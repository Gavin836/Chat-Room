#coding: utf-8
from socket import *
import datetime as dt
import threading
import select
import time
import sys
import string

# Constants
BUFLEN = 2048

# Global variables, TODO: add synchronisation
connections = []  # List of tuples of (socket, addr)
clientSockets = [] # List of sockets to read from
t_lock=threading.Condition() # Lock to ensure shared structures of thread are deadlock free

# The objects responsible to authenticating users. 
# All entries loaded at start time
class authObj:
    def __init__(self, user, passwd):
        self.user = user
        self.passwd = passwd
        self.loginAttempts = 0

# Provide methods to access and process authObjs
class authList:
    def __init__(self, maxLoginAttempts):
        self.authList = []
        self.maxLoginAttempts = maxLoginAttempts
        
        fd = open("credentials.txt", "r")
        for line in fd.readlines():
            res = line.split()
            self.insert(res[0], res[1])        
    
    # Check if user/pass combination is in list
    # ret 0 = login valid
    # ret -1 = failed login (different ip). fail counter incremented
    # ret -2 = failed login (different ip). fail counter incremented
    # ret -3 = failed login and timing out. signal to reset counter

    def auth(self, user, passwd):
        
        for authObj in self.authList:
            if (authObj.user == user):
                if (authObj.loginAttempts == self.maxLoginAttempts):
                    return -3
                
                if (authObj.passwd == passwd):
                    return 0;
                else:
                    authObj.loginAttempts = authObj.loginAttempts + 1
                    if (authObj.loginAttempts != self.maxLoginAttempts):
                        return -1
                    else:
                        return -2
    
        return -1;
    # Reset login attempt after 10 secs
    def resetAttempts(self, user):
        for authObj in self.authList:
            if (authObj.user == user):
                time.sleep(10);
                authObj.loginAttempts = 0
        
    def insert(self, user, passwd):
        self.authList.append(authObj(user, passwd))
        
    def is_empty(self):
        return (len(self.authList) == 0)

# Data structure used to stored information on clients session.
# Entries are populated when users are logged on (removed otherwise)
class clientObj:
    def __init__(self, user, seq, connection, port):
        self.user = user
        self.seqNumber = seq
        self.ip = connection[1][0]
        self.socket = connection[0]
        self.udpPort = port
        self.time = dt.datetime.now().strftime("%d/%m/%Y %H:%M:%S")
    
    # String for printing within server
    def getStr(self):
        return "{}; {}; {}; {}; {}".format(self.seqNumber, self.time, self.user, self.ip, self.udpPort)
    
    # String for printing at clients
    def clientPrint(self):
        return (self.user + "(IP: {}, PORT {})".format(self.ip, self.udpPort) 
                         + " online since " + self.time)
        
    def destroy(self):
        close(self.fd)

# List of clientObj, and methods to process it.
class clientList:
    def __init__ (self):
        self.clientList = []
        
    def clientAdd(self, user, connection, udpPort):
        seqNo = len(self.clientList) + 1
        self.clientList.append(clientObj(user, seqNo, connection, udpPort))
        self.__writeLog()
    
    def findObj(self, user):
        for i in self.clientList:
            if i.user == user:
                return i
    
    def __writeLog(self):
        cObj = self.clientList[-1]
        print("Writing to log: " + cObj.getStr() + "\n")
        with open("userlog.txt", "a") as f:
            f.write(cObj.getStr() + "\n")
            
    def clientRemove(self, name):
        self.clientList.remove(self.findObj(name))
    
    # Return list of active users that are not "name"
    def getOthers(self, name):
        retList = []
        for client in self.clientList:
            # Strcmp != 0, remove the users with "name"
            if (not(len(name) == len(client.user))):
                if (not(name in client.user)):
                    retList.append(client)
        
        return retList
            
# Used for storing messages with associated metadata
class msgObj:
    def __init__ (self, id, fromUser, content):
        self.id = id
        self.time = dt.datetime.now().strftime("%d/%m/%Y %H:%M:%S")
        self.fromUser = fromUser
        self.content = content
        self.modified = False
    
    # For printing within server
    def getStr(self):
        return "{}; {}; {}; {}; {}".format(self.id, self.time, self.fromUser, 
                                           self.content, self.modified)
    
    # For printing at client
    def clientPrint(self):
        if (self.modified):
            return "#{}, {} edited \"{}\" at {}".format(self.id, self.fromUser, 
                                                        self.content, self.time)
        else:
            return "#{}, {} posted \"{}\" at {}".format(self.id, self.fromUser, 
                                                        self.content, self.time)
# Data structure for editing the list of message
class msgList:
    def __init__ (self):
        self.msgList = []
        self.id = 1
        
        # Flush the messagelog from previous executions
        with open("messagelog.txt", "w") as f:
            f.write("")
    
    def addMsg(self, fromUser, content):
        obj = msgObj(self.id, fromUser, content)
        self.msgList.append(obj)
        self.id = self.id + 1
        
        self.__writeLog()
        return obj
    
    # Remove from list and logfile
    def delMsg(self, user, msgID, time):
        for i in self.msgList:
            if (i.id == int(msgID)):
                if (i.time == time):
                    if (i.fromUser == user):
                        self.__rmLog(i)
                        self.msgList.remove(i)
                        return 0
                    return 1
                return 2
        return 3
    
    # Modify entries in list and logfile
    def modMsg(self, user, msgID, time, newContent):
        for i in self.msgList:
            if (i.id == int(msgID)):
                if (i.fromUser == user):
                    i.time = time
                    i.modified = True
                    i.content = newContent
                    self.__modLog(i)
                    return 0
                return 1
        return 2
    
    # Append to log file
    def __writeLog(self):
        msgObj = self.msgList[-1]
        print("Writing to log: " + msgObj.getStr() + "\n")
        with open("messagelog.txt", "a") as f:
            f.write(msgObj.getStr() + "\n")
    
    # Remove entry from log file by copying and replacing
    def __rmLog(self, obj):
        with open("messagelog.txt", "r") as f:
            lines = f.readlines()
        with open("messagelog.txt", "w") as f:
            for line in lines:
                msgId = (line.split(";"))[0]
                if (int(msgId) != obj.id):
                    f.write(line)
    
    # Modify particular entry in logfile
    def __modLog(self, obj):
        with open("messagelog.txt", "r") as f:
            lines = f.readlines()
        with open("messagelog.txt", "w") as f:
            for line in lines:
                msgId = (line.split(";"))[0]
                if (int(msgId) != obj.id):
                    f.write(line)
                else:
                    f.write(obj.getStr())
    
    def toRead(self, user, time):
        retList = []
        afterTime = dt.datetime.strptime(time, "%d/%m/%Y %H:%M:%S")
        for msg in self.msgList:
            msgTime = dt.datetime.strptime(msg.time, "%d/%m/%Y %H:%M:%S")
            if (msgTime > afterTime):
                if (not((len(user) == len(msg.fromUser)) and (user in msg.fromUser))):
                    retList.append(msg)
                
        return retList;
            
def recv_handler():
    global t_lock         # Control access to shared data structures
    global connections    # List of (sockets, addr) 
    global clientSockets  # List of active user's sockets
    global serverSocket   # The server socket for recv connections
    
    print('Server is ready for service')
    while(1):
        # Wait until a socket can be accepted or read from
        rlist, wlist, xlist = select.select( [serverSocket] + clientSockets, [], [] )
        
        # Enter critical section
        with t_lock:
            for curSocket in rlist:
                # Handle new connections
                if (curSocket == serverSocket):
                    newSocket, addr = curSocket.accept()
                    connections.append((newSocket, addr))
                    clientSockets.append(newSocket)

                # Handle requests from existing clients
                else:
                    sentence = curSocket.recv(BUFLEN)
                    sentence = sentence.decode()
                    if (sentence):
                        # Handle waiting blocking event
                        requestHand=threading.Thread(name="requestHand", target=handleRequest(curSocket, sentence))
                        requestHand.daemon=True
                        requestHand.start()                            
                    else:
                        clientSockets.remove(curSocket)
                        for i in connections:
                            if i[0] == curSocket:
                                connections.remove(i)
                
                        curSocket.close()
            
            # Leave critical section
            t_lock.notify()

def handleRequest(sockfd, sentence):
    global authenticator # Used for process authObj 
    global activeUsers   # Used to process clientObj
    global msgHist       # Used to process messageObj
    global clientSockets # List of active client sockets
    global connections   # List of tuples of (sockets, addr)
    
    # Extract client CMD and username
    args = sentence.split(" ")
    user = args[0]
    
    print(args[1])
    if (args[0] == "AUTH"):
        user = args[1]
        passwd = args[2]
        udpPort = args[3]
        result = authenticator.auth(user, passwd)
        
        if (result == 0):
            for i in connections:
                if i[0] == sockfd:
                    activeUsers.clientAdd(user, i, udpPort)
            
            sendStr = "OK"
            print("Sucessfully authenticated: " + user)

        if (result == -1):
            sendStr = "FAIL"
            print("Failed authentication - " + user + " / " + passwd)

        if (result == -2):
            authenticator.resetAttempts(user)
            sendStr = "TIMEOUT"
            print("Failed authentication. Send timeout - " + user + " / " + passwd)
        
        if (result == -3):
            sendStr = "TIMEOUT"
            print("Attempt to access timedout account. Send timeout -" + user + " / " + passwd)

    elif (args[1] == "MSG"):
        # Split twice to preserve message as one string. Sentence format  = USER MSG MESSAGE
        args = sentence.split(" ", 2)
        
        # No arguments to MSG
        if (len(args) == 2):
            sendStr = "MSGLEN"
        else:
            message = args[2]

            msgObj = msgHist.addMsg(user, message)
                        
            sendStr = "MSG {} {}".format(msgObj.time, msgObj.id)  
            print("{} posted MSG #{} \"{}\" at {}".format(msgObj.fromUser, msgObj.id, message, msgObj.time))
    
    elif (args[1] == "DLT"):
        # Sentence format  = USER DLT MSGID TIMESTAMP 
        args = sentence.split(" ", 3)
        if (len(args) != 4):
            sockfd.send("DLTID".encode())
            print(user + " failed DLT with wrong number of arguments")
            return;
        
        user = args[0]
        msgID = args[2]
        time = args[3]
        
        result = msgHist.delMsg(user, msgID, time)
        if (result == 0):
            sendStr = "DLTYES"
            print(user + " deleted MSG #{} at {}". format(msgID, time))
        elif(result == 1):
            sendStr = "DLTUSER"
            print(user + " failed DLT #{} at {}". format(msgID, time))

        elif(result == 2):
            sendStr = "DLTTIME"
            print(user + " failed DLT #{} at {}". format(msgID, time))

        else:
            sendStr = "DLTID"
            print(user + " failed DLT #{} at {}". format(msgID, time))
            
    elif (args[1] == "EDT"):
        # Sentence format = USER EDT MSGID TIME1 TIME2 MESSAGE
        args = sentence.split(" ", 5)
        
        if (len(args) != 6):
            sockfd.send("EDTID".encode())
            print(user + " failed EDT")
            return;
            
        msgID = args[2]
        time = args[3] + " " + args[4]
        nMsg = args[5]
        
        result = msgHist.modMsg(user,msgID, time, nMsg)
        
        if (result == 0):
            sendStr = "EDTYES"
            print(user + " modified MSG #{} to {} at {}".format(msgID, nMsg, time))
        elif (result == 1):
            sendStr = "EDTUSER"
            print(user + " failed EDT #{} at {}".format(msgID, time))
        else:
            sendStr = "EDTID"
            print(user + " failed EDT #{} at {}".format(msgID, time))
        
    elif (args[1] == "RDM"):
        # Sentence format USER RDM TIME
        args = sentence.split(" ", 2)
        
        if (len(args) != 3):
            sockfd.send("RDMF".encode())
            print(user + " failed RDM")
            return;
        
        time = args[2]
        
        toReadList = msgHist.toRead(user, time)
        if (len(toReadList) == 0):
            sendStr = "RDMT No recent messages found"
            print(user + " RDM none at {}".format(time))
        else:
            sendStr = "RDMT "
            for i in toReadList:
                sendStr = sendStr + i.clientPrint() + "\n"
            
            print(user + " issued RDM sending: {}\n".format(sendStr))

        
    elif (args[1] == "ATU"):
        # No arguments
        onlineUsers = activeUsers.getOthers(user)
        if (len(onlineUsers) == 0):
            sendStr = "ATU No other users online"
            print(user + " RDM returned no other users online")
        else:
            sendStr = "ATU "
            for i in onlineUsers:
                sendStr = sendStr + i.clientPrint() + "\n"
            
            print(user + " issued ATU command sending: \n{}".format(sendStr))
    
    elif (args[1] == "UDP"):
        pass

    elif (args[1] == "OUT"):
        clientSockets.remove(sockfd)
        
        # Remove entry from connections struct
        for i in connections:
            if i[0] == sockfd:
                connections.remove(i)
        
        # Remove entry from active user's list using sockfd as ID
        activeUsers.clientRemove(user)
        
        print("Sucessfully logged out " + "user")

        sendStr = "EXIT"
        sockfd.send("EXIT".encode())
        sockfd.close()
        return;
    
    else:
        sendStr = "UNKNOWN"
    
    sockfd.send(sendStr.encode("utf-8"))


################################################################################
# Main Thread
# Unpack arguments
if (len(sys.argv) != 3):
    print("Invalid Argument: ./server portNO loginAttemptsNum")
    exit()
    
#Define connection (socket) parameters
serverPort = int(sys.argv[1])
maxLoginAttempts = int(sys.argv[2])

if (type(serverPort) != int):
    print("Invalid server port argument")
    
if (maxLoginAttempts < 1 or maxLoginAttempts > 5):
    print ("Invalid login attempt argument")

#Setup IPv4 TCP sockets
serverSocket = socket(AF_INET, SOCK_STREAM)
serverSocket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)

clientSocket = socket(AF_INET, SOCK_STREAM)

serverSocket.bind(('localhost', serverPort))

#The serverSocket then goes in the listen state to listen for client connection requests. 
serverSocket.listen(50)
authenticator = authList(maxLoginAttempts)
activeUsers = clientList()
msgHist = msgList()

print ("The server is ready to receive")

recv_thread=threading.Thread(name="RecvHandler", target=recv_handler)
recv_thread.daemon=True
recv_thread.start()

while (1):
    time.sleep(0.1)
        
