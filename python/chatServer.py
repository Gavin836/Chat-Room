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
connections = []
clientSockets = []
t_lock=threading.Condition()

class authObj:
    def __init__(self, user, passwd):
        self.user = user
        self.passwd = passwd
        self.loginAttempts = 0

class authList:
    def __init__(self, maxLoginAttempts):
        self.authList = []
        self.maxLoginAttempts = maxLoginAttempts
        
        fd = open("credentials.txt", "r")
        for line in fd.readlines():
            res = line.split()
            self.insert(res[0], res[1])        
    
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
    
    def resetAttempts(self, user):
        for authObj in self.authList:
            if (authObj.user == user):
                time.sleep(10);
                authObj.loginAttempts = 0
        
    def insert(self, user, passwd):
        self.authList.append(authObj(user, passwd))
        
    def is_empty(self):
        return (len(self.authList) == 0)
        
class clientObj:
    def __init__(self, user, seq, connection, port):
        self.user = user
        self.seqNumber = seq
        self.ip = connection[1][0]
        self.socket = connection[0]
        self.udpPort = port
        self.time = dt.datetime.now().strftime("%d/%m/%Y %H:%M:%S")
    
    def getStr(self):
        return "{}; {}; {}; {}; {}".format(self.seqNumber, self.time, self.user, self.ip, self.udpPort)
    
    def clientPrint(self):
        return (self.user + "(IP: {}, PORT {})".format(self.ip, self.udpPort) 
                         + " online since " + self.time)
        
    def destroy(self):
        close(self.fd)
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
    
    def getOthers(self, name):
        retList = []
        for user in self.clientList:
            if (not((len(name) != len(user.user)) and (name in user))):
                retList.append(user)
        
        return retList
            

class msgObj:
    def __init__ (self, id, fromUser, content):
        self.id = id
        self.time = dt.datetime.now().strftime("%d/%m/%Y %H:%M:%S")
        self.fromUser = fromUser
        self.content = content
        self.modified = False
    
    def getStr(self):
        return "{}; {}; {}; {}; {}".format(self.id, self.time, self.fromUser, 
                                           self.content, self.modified)
    
    def clientPrint(self):
        if (modified):
            return "#{}, {} edited \"{}\" at {}".format(self.id, self.fromUser, 
                                                        self.content, self.time)
        else:
            return "#{}, {} posted \"{}\" at {}".format(self.id, self.fromUser, 
                                                        self.content, self.time)
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
    
    
    def __writeLog(self):
        msgObj = self.msgList[-1]
        print("Writing to log: " + msgObj.getStr() + "\n")
        with open("messagelog.txt", "a") as f:
            f.write(msgObj.getStr() + "\n")
    
    def __rmLog(self, obj):
        with open("messagelog.txt", "r") as f:
            lines = f.readlines()
        with open("messagelog.txt", "w") as f:
            for line in lines:
                msgId = (line.split(";"))[0]
                if (int(msgId) != obj.id):
                    f.write(line)
    
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
        afterTime = datetime.strptime(time, "%d/%m/%Y %H:%M:%S")
        for msg in msgList:
            msgTime = datetime.strptime(msg.time, "%d/%m/%Y %H:%M:%S")
            if (msgTime > afterTime):
                if (not((len(user) == len(msg.user)) and (user in msg.user))):
                    retList.append(msg)
                
        return retList;
            
def recv_handler():
    global t_lock
    global connections
    global clientSockets
    global serverSocket
    
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
                
def send_handler():
    global t_lock
    global clientSocket
    global serverSocket
    global activeUsers
    global msgHist
    
    msgIndex = 0
    # Continous loop until new message is found. Send to all active users.
    while(1):
        #get lock
        with t_lock:
            msgObj = msgHist.getUnsentMsg(msgIndex)
            if (msgObj != NULL):
                onlineUsers = activeUsers.clientList
                sendStr = "NEWMSG {} {} {} {}".format(msgObj.fromUser, msgObj.id, msgObj.contents, msgObj.time)
                for i in onlineUsers:
                    i.socket.send()
                
                msgIndex = msgIndex + 1
                
            
            #notify other thread
            t_lock.notify()
        #sleep for UPDATE_INTERVAL
        time.sleep(UPDATE_INTERVAL)

def handleRequest(sockfd, sentence):
    global authenticator
    global activeUsers
    global msgHist
    global clientSockets
    global connections
    
    args = sentence.split(" ")
    user = args[0]

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
        
        if (len(args) != 4):
            sockfd.send("DLTID".encode())
            print(user + " failed DLT")
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
            print(user + " modified MSG #{} to {} at {}". format(msgID, nMsg, time))
        elif (result == 1):
            sendStr = "EDTUSER"
            print(user + " failed EDT #{} at {}". format(msgID, time))
        else:
            sendStr = "EDTID"
            print(user + " failed EDT #{} at {}". format(msgID, time))
        
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
            print(user + " RDM none at {}". format(time))
        else:
            sendStr = "RDMT "
            for i in toReadList:
                sendStr = sendStr + i.clientPrint() + "\n"
            
            print(user + " issued RDM sending: {}\n".format(sendStr))

        
    elif (args[1] == "ATU"):
        # No arguments
        onlineUsers = activeUsers.getOthers(user)
        if (len(onlineUsers) == 0):
            sendStr = "ATU No recent messages found"
            print(user + " RDM none at {}". format(time))
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

# send_thread=threading.Thread(name="SendHandler",target=send_handler)
# send_thread.daemon=True
# send_thread.start()

while (1):
    time.sleep(0.1)
        
