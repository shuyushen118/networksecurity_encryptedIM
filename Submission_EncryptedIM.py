from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto import Random
from base64 import b64decode
from Crypto.Hash import HMAC
import hashlib
import base64
import hmac
import socket
import sys
import select
import argparse
import signal

SOCKET_LIST = [];

def initialize(key):
    hash_obj = hashlib.sha256()
    hash_obj.update(key)
##    print (hash_obj.digest_size)
##    print (hash_obj.block_size)
    
    return hash_obj.digest()

#hash the message with key
def hasher(key,msg):
    hashed_obj = hmac.new(key,msg,hashlib.sha256)
    return hashed_obj.hexdigest()

def encrypt( key1,key2,raw):
    BS = 16
    pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS) 
    unpad = lambda s : s[:-ord(s[len(s)-1:])]
    #initialize the key
    confy_key = initialize(key1)
    auth_key = initialize(key2)
    
    #hash the message with raw message and key 2
    hashed_msg = hasher(auth_key,raw)
##    print(hashed_msg)z
    #add original message to the hashed message
    pack = pad (raw +'|'+ hashed_msg)
    #encrypt the whole thing
    #generate iv randomly
    iv = Random.new().read(16)
    #use AES to encrypt the whole thing
    cipher = AES.new( confy_key, AES.MODE_CBC, iv )
    en_mesg = cipher.encrypt(pack)
    return base64.b64encode (iv + en_mesg)

def decrypt(key1,key2,en_msg):
    BS = 16
    pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS) 
    unpad = lambda s : s[:-ord(s[len(s)-1:])]
    #initialize the key
    confy_key = initialize(key1)
    auth_key = initialize(key2)
    #decode
    en_msg = base64.b64decode(en_msg)
    #got iv in the recived messag
    iv = en_msg[:16]
    #decrypt and unpad pack
    cipher = AES.new(confy_key, AES.MODE_CBC, iv )
    de_message = unpad(cipher.decrypt( en_msg[16:] ))
    index_sep = de_message.find('|')
##    print(de_message[:index_sep])
    mesg_recived = de_message[:index_sep]
    #hash the message recived
    hashed_msg = hasher(auth_key,mesg_recived)
##    print (hashed_msg)
    hash_recived = de_message[index_sep + 1:]
    if (hashed_msg == hash_recived):
        return mesg_recived
    else:
        raise Exception("Authentification failed, breaking connaction")

    #compare the computed mesage to the hased message in the pack

def handler(signum,frame):
    """ handle a SIGINT (ctrl-C) keypress """
    for s in SOCKET_LIST:                 #close all sockets
        s.close()
    sys.exit(0)

#server program
def s(confy_key, authen_key):
    HOST =''
    PORT = 9999
    #create an INET, STREAMing socket
    listen_socket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    #set to reuse address
    listen_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    #bind socket to an address
    listen_socket.bind((HOST, PORT))
    #listen for connections made to socket, 10 is the maxium que connection 
    listen_socket.listen(10)
    #empty socket
    client_socket = []
    #infinite loop for reciving signal 
    while True:
        #list store keyboardinput and established connection 
        inputs = [sys.stdin,listen_socket]+client_socket
        #using select to store data and not blocking communication
        read_list, write_list, error = select.select(inputs,[],[])
        for r in read_list:
            #a new connection established
            if r is listen_socket:
                conn,addr = r.accept()
                #add new connection to the client socket list
                client_socket.append(conn)
                #send new message
            #moniter is there any input from the keyboard
            elif r is sys.stdin:
                #message enter from keyboard, sending message
                msg = sys.stdin.readline()
                #encrypt message 
                en_msg = encrypt(confy_key,authen_key,msg)
                conn.send(en_msg)
                sys.stdout.flush()
            #no message input then waiting for incoming message from client
            else:
                msg = conn.recv(1024)
                #decrypt message
                if msg =="":
                    break;
                de_mesg = decrypt(confy_key,authen_key,msg)
                sys.stdout.write(de_mesg)
                sys.stdout.flush()


#client program
def c(confy_key,authen_key):
##    print ("in the client")
    HOST =''
    PORT =9999
    #create an INET, STREAMing socket
    connect_socket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    connect_socket.connect((HOST,PORT))
    while True:
        #list store any keyboard input and coming message
        inputs = [sys.stdin, connect_socket]
        read_list, write_list, error = select.select(inputs,[],[])
        for r in read_list:
            #a new connection established and message is comming in
            if r is connect_socket:
                msg = r.recv(1024)
                #decrypt message
                if msg == "":
                    break;
                de_mesg = decrypt(confy_key,authen_key,msg)
                sys.stdout.write (de_mesg)
                sys.stdout.flush()
            #keyboard entered, ready to send message 
            elif r is sys.stdin:
                outgoing_message = sys.stdin.readline()
                #encrypt message
                en_msg = encrypt(confy_key,authen_key,outgoing_message)
                connect_socket.send(en_msg)
                sys.stdout.flush()

#main
#get command line argument and decide which function to run
##print 'Number of arguments:', len(sys.argv),'arguments.'
argv_1 = sys.argv[1]
confy_key = sys.argv[2]
authen_key = sys.argv[3]

signal.signal(signal.SIGINT,handler)

if argv_1 == "--s":
    s(confy_key,authen_key)
elif argv_1 == "--c":
    c(confy_key,authen_key)
for sock in SOCKET_LIST:
    sock.close();
sys.exit(0);
