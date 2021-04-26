#coding: utf-8
from socket import *
import sys
import time

BUFLEN = 2048

if (len(sys.argv) != 4):
    print("Wrong number of arguments ./client ip port udpPort")
    exit(0)
    
#Define connection (socket) parameters
serverName = sys.argv[1]
serverPort = int(sys.argv[2])
clientUDP = int(sys.argv[3])

clientSocket = socket(AF_INET, SOCK_STREAM)
#This line creates the client’s socket. The first parameter indicates the address family; in particular,AF_INET indicates that the underlying network is using IPv4. The second parameter indicates that the socket is of type SOCK_STREAM,which means it is a TCP socket (rather than a UDP socket, where we use SOCK_DGRAM). 

clientSocket.connect((serverName, serverPort))
#Before the client can send data to the server (or vice versa) using a TCP socket, a TCP connection must first be established between the client and server. The above line initiates the TCP connection between the client and server. The parameter of the connect( ) method is the address of the server side of the connection. After this line of code is executed, the three-way handshake is performed and a TCP connection is established between the client and server.

# Authentication loop - Inteprets results from authentication
while (1):
    user = input("Enter username: ")
    passwd = input ("Enter password: ")
    
    sentence = "AUTH" + " " + user + " " + passwd + " " + str(clientUDP)
    clientSocket.send(sentence.encode('utf-8'))
    
    result = clientSocket.recv(BUFLEN)
    result = result.decode()
    
    print("#SERVER RESPONSE: " + result)
    if (result == "TIMEOUT"):
        print("Too many incorrect login attempts have been made. Waiting 10 seconds...")
    
    elif (result == "FAIL"):
        print("Incorrect login")
    
    elif (result == "OK"):
        print("Sucess! Welcome " + user)
        break;

# Upon authentication, enter command loop
while (1):
    cmd = input('Please enter a command (MSG, DLT, EDT, RDM, ATU, UDP)\n')
    sendStr = user + " " + cmd
    clientSocket.send(sendStr.encode('utf-8'))
    
    #We wait to receive the reply from the server
    result = clientSocket.recv(BUFLEN)
    result = result.decode()
    print("#SERVER RESPONSE: " + result)

    if ("EXIT" in result):
        print("Goodbye!")
        exit(0)
    
    elif("MSGLEN" in result):
        print("MSG no argument. Try again! Eg. $MSG MESSAGE")
    
    elif("MSG" in result):
        args = result.split()
        time1 = args[1]
        time2 = args[2]
        sendID = args[3]
        print("Message #{} posted at {} {}".format(sendID, time1, time2))
    
    elif("DLTYES" in result):
        print("Message deleted")
    
    elif("DLTID" in result):
        print("Message NOT deleted: Invalid message id. Eg. $DLT ID d/m/Y H:M:S")
        
    elif("DLTTIME" in result):
        print("Message NOT deleted: Invalid time or time format. Eg. $DLT ID d/m/Y H:M:S")

    elif("DLTUSER" in result):
        print("Message NOT deleted: Message not by user. Eg. $DLT ID d/m/Y H:M:S")
    
    elif("EDTYES" in result):
        print("Message edited")
    
    elif("EDTID" in result):
        print("Message NOT edited: Invalid message id. Eg. $EDT ID d/m/Y H:M:S MESSAGE")
        
    elif("EDTUSER" in result):
        print("Message NOT edited: Message not by user. Eg. $EDT ID d/m/Y H:M:S MESSAGE")

    elif("RDMF" in result):
        print("RDM not executed: Invalid time. Eg. $RDM d/m/Y H:M:S")
    
    elif("RDMT" in result):
        # Remove RDMT header
        sendStr = result.split(" ", 1);
        print(sendStr[1])
        
    elif("ATU" in result):
        # Remove ATU header
        sendStr = result.split(" ", 1);
        print(sendStr[1])
        
    elif(result.contains("UPD")):
        pass
    else:
        printf("Unknown command. Try again")

clientSocket.close()
#and close the socket
