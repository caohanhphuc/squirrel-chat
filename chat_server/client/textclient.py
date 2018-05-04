from threading import *
from socket import *
import exceptions
import errno
import atexit
import signal
import subprocess
import time
import sys
import os
from os import stat
import ssl

#from __future__ import absolute_import, division, print_function
import nacl.utils
from nacl.public import PrivateKey, Box
import nacl.bindings
from nacl import encoding
from nacl import exceptions as exc
from nacl.utils import EncryptedMessage, StringFixer, random

channels = {}
CERT = "../cert.pem"
KEY = "../key.pem"
BUFFER_SIZE = 1024

class RecvLoop(Thread):
    def __init__(self,socket,client):
        Thread.__init__(self)
        self.socket = socket
        self.client = client

    def run(self):
        print("Accepting data from server.")
        while True:
            d = self.socket.recv(BUFFER_SIZE)
            print ("----- server data received ------")
            #print(d)
            result = self.client.handle(d)
            print ("----------------------------------")
            sys.stdout.write('>')
            sys.stdout.flush()
'''
class GetDownload(Thread):
    def __init__(self, des_name, filepath, filesize, connection):
        Thread.__init__(self)
        self.des_name = des_name
        self.filepath = filepath
        self.filesize = filesize
        self.connection = connection
'''

def get_download(des_name, filepath, filesize, connection):
    received = 0
    fileinfo = filepath.split('/')
    filename = fileinfo[len(fileinfo) - 1]
    dirpath = filepath[:len(filepath) - len(filename)-1]
    print ("idirpath is in get download %s." % dirpath)
    if not os.path.exists(dirpath):
        os.makedirs(dirpath)
    print ("in get download file name is %s." % filepath)
    try:
        with open(filepath, 'wb') as write_file:
            while received < filesize:
                remainbytes = filesize - received
                bytes_to_get = BUFFER_SIZE if remainbytes > BUFFER_SIZE else remainbytes
                getfile = connection.recv(bytes_to_get)
                received += bytes_to_get
                write_file.write(getfile)
    except IOError:
        connection.send("Error: download file {} failed.\n".format(filename))
        while received < filesize:
                remainbytes = filesize - received
                bytes_to_get = BUFFER_SIZE if remainbytes > BUFFER_SIZE else remainbytes
                getfile = connection.recv(bytes_to_get)
                received += bytes_to_get
    except OSError as e:
        print ("Socket error: %d" % e.errno)
    return received

def get_filelist(number, connection):
    got = 0
    try:
        while got < number:
            filename = connection.recv(BUFFER_SIZE)
            print (filename)
            got += 1
    except OSError as e:
        print ("Socket error: %d" % e.errno)
    return got

class Client(Thread):
    def __init__(self,server,port):
        Thread.__init__(self)
        self.server = server
        self.port = port
        self.start()
        self.channels = {}
        self.current_channel = None
        self.current_user = None
        self.connection = None
        self.logged_in = False
        self.private_key = PrivateKey.generate()
        self.public_key = self.private_key.public_key
        self.peer_public_key = {}

    def run(self):
        print("Connecting to server...")
        self.connection = socket(AF_INET, SOCK_STREAM)
        self.connection = ssl.wrap_socket(self.connection, ca_certs=CERT, cert_reqs=ssl.CERT_REQUIRED)
        try:
            self.connection.connect((self.server,self.port))
            print("Connected!")
        except:
            self.connection.close()
            sys.exit(0)
        print("Welcome to SquirrelChat!")
        print("Not logged in yet, either /authenticate or /register\n")
        print("Commands:\n")
        print("/join #channel")
        print("/chat <username/#channel> <message>")
        print("/register <username> <password>")
        print("/authenticate <username> <password>")
        print("/topic <new topic> <-- Sets topic for current channel")
        print("/block <username>")
        print("/ban <username> <channel>")
        print("/ban <username> <channel>")
        print("/unban <username> <channel>")
        print("/exchanagekey <username> <username>")
        print("/privmsg <username> << open up chat with <username>")
        print("/getfiles <username/#channel>")
        print("/upload <username/#channel> ")
        print("/update <username/#channel>")
        print("/remove <username/#channel>")
        print("/exit")
        self.loop()

    def display_chat(self,entity,chat):
        print("{}> {}".format(entity,chat))

    # Handle a message from the server
    def handle(self,d):
        print("in handle, textclient.py")
        pieces = d.split()
        if len(pieces) == 0:
            print("Error: Empty packet!")
            exit(1)
        # These are the only things that should come back from the server
        elif pieces[0] == "chatfrom":
            chat = d.split(' ', 3)
            fromwhom = chat[1]
            towhom = chat[2]
            text = chat[3]
            if towhom.startswith("#"):
                msg = "charfrom {} {} {}\n".format(fromwhom, towhom, text)
                print(msg)
            else:
                if fromwhom in self.peer_public_key:
                    peer_pubkey = self.peer_public_key[fromwhom]
                    local_box = Box(self.private_key, peer_pubkey)
                    try:
                        plaintext = local_box.decrypt(text)
                        msg = "chatfrom {} {} {}".format(fromwhom, towhom, plaintext)
                        print(msg)
                    except Exception:
                        print("Error: fail to decrypt message from %s.\n" % (fromwhom))
                        return False 
                else:
                    try:
                        raise Exception("Error: message cannot be verified and decrypted")
                    except Exception:
                        err = "Error: need public key from {}. Exchange key before chat\n".format(fromwhom)
                        print(err)
                #msg = "chatfrom {} {} {}".format(fromwhom, towhom, plaintext)
                #print(msg)
            if not chat[2] in self.channels:
                # Notify the user of the first chat on a channel
                self.channels[chat[2]] = [(chat[1],chat[3])]
                #print("Attention: First chat on channel {}".format(chat[2]))
            else:
                # Log this in case they go back later
                self.channels[chat[2]].append((chat[1],chat[3]))
            if self.current_channel == chat[2]:
                self.display_chat(chat[1],chat[3])
            return True
        elif pieces[0] == "topic":
            topic = d.split(' ', 2)
            print("The topic for {} is {}".format(topic[1],topic[2]))
            return True
        elif pieces[0] == "error":
            print("Error! {}".format(d.split(' ', 1)[1]))
            return True
        elif pieces[0] == "exit":
            self.connection.close()
            os._exit(0)
            return False
        elif pieces[0] == "exchangekey":
            exchange = d.split(' ', 3)
            #need to send back the public key
            peer_user = exchange[1]
            key = nacl.public.PublicKey(exchange[3])
            if peer_user in self.peer_public_key:
                return True
            self.peer_public_key[peer_user] = key
            msg = "/exchangekey {} {}".format(self.current_user, peer_user)
            print("going to handle input in handle()")
            self.handle_input(msg)
        elif pieces[0] == "file":
            download = d.split(' ', 3)
            if len(download) == 4:
                des_name = download[1]
                filepath = download[2]
                filesize = int(download[3])
                thread = Thread(target=get_download, args=(des_name, filepath, filesize, self.connection))
                thread.start()
                thread.join()
            else:
                print("Error: download file failed")
        elif pieces[0] == "getfiles":
            print(d)
            #getfile = d.split(' ', 2)
            #if len(getfile) == 3:
                #size = int(getfile[2])
                #print("%s contains following files:" % getfile[1])
                #getlist = Thread(target=get_filelist, args=(size, self.connection))
                #getlist.start()
                #getlist.join()
            #else:
                #print("Error: getfiles failed")
        else:
            #print("The server has sent back a response I can't parse:")
            print(d)
            return True

    # Note: Doesn't check whether channel login was successful
    def change_to(self,channel):
        self.current_channel = channel
        print("Changed to channel {}".format(self.current_channel))
        # To all you students: perhaps think about showing the sent
        # since the last time that the user logged into this channel.

    # Note: No checking on the client end
    def handle_input(self,i):
        print("in handle_input, textclient.py")
        cmd = i.split()
        if (len(cmd) == 0):
            print("Invalid input")
            return
        if (cmd[0] == "/join"):
            if self.logged_in == True:
                print("Joining {}..".format(cmd[1]))
                self.send("join {}".format(cmd[1]))
                time.sleep(.2)
                self.send("gettopic {}".format(cmd[1]))
                self.change_to(cmd[1])
            else:
                print("Error: user not logged in")
        elif (cmd[0] == "/register"):
            if len(cmd) != 3:
                print("Error: Invalid input")
                return
            print("Registering...")
            self.send("register {} {}".format(cmd[1],cmd[2]))
            self.logged_in = True
            self.current_user = cmd[1]
        elif (cmd[0] == "/authenticate"):
            if len(cmd) != 3:
                print("Error: Invalid input")
                return
            self.send("authenticate {} {}".format(cmd[1],cmd[2]))
            self.logged_in = True
            self.current_user = cmd[1]
        elif (cmd[0] == "/gettopic"):
            if len(cmd) != 2:
                print("Error: Invalid input")
                return
            if self.logged_in == True:
                self.send("gettopic {}".format(cmd[1]))
            else:
                print("Error: user not logged in")
        elif (cmd[0] == "/settopic"):
            if len(cmd) < 3:
                print("Error: Invalid input")
                return
            if self.logged_in == True:
                self.send("settopic {} {}".format(cmd[1],i.split(' ', 2)[2]))
            else:
                print("Error: user not logged in")
        elif (cmd[0] == "/block"):
            if len(cmd) != 2:
                print("Error: Invalid input")
                return
            if self.logged_in == True:
                self.send("block {}".format(cmd[1]))
            else:
                print("Error: user not logged in")
        elif (cmd[0] == "/ban"):
            if len(cmd) != 3:
                print("Error: Invalid input")
                return
            if self.logged_in == True:
                self.send("ban {} {}".format(cmd[1],cmd[2]))
            else:
                print("Error: user not logged in")
        elif (cmd[0] == "/privmsg"):
            print("Now in private message with user {}".format(cmd[1]))
            self.change_to(cmd[1])
        elif (cmd[0] == "/unban"):
            if len(cmd) != 3:
                print("Error: Invalid input")
                return
            if self.logged_in == True:
                self.send("unban {} {}".format(cmd[1],cmd[2]))
            else:
                print("Error: user not logged in")
        elif (cmd[0] == "/exit"):
            self.send("exit")
        # exchangekey <fromuser> <touser>
        elif (cmd[0] == "/exchangekey"):
            if len(cmd) != 3:
                print("Error: Invalid input")
                return
            # send to server 'exchangekey <fromuser> <touser> <key.seralized>'
            if self.logged_in == True:
                if cmd[1] != self.current_user and cmd[2] != self.current_user:
                    print("Error: Cannot only exchange your key with one other's")
                    return False
                key = nacl.encoding.RawEncoder.encode(self.public_key)
                self.send("exchangekey {} {} {}".format(cmd[1], cmd[2], key))
            else:
                print("Error: user not logged in")
        elif (cmd[0] == "/chat"):
            if len(cmd) < 3:
                print("Error: Invalid input")
                return
            if self.logged_in == False:
                print("Error: user not logged in")
                return False
            parsechat = i.split(' ', 2)
            to_chat = parsechat[1]
            chatmsg = parsechat[2]
            if to_chat.startswith("#"):
                self.send("chat {} {} {}".format(to_chat, chatmsg, " "))
            else:
                if to_chat in self.peer_public_key:
                    peer_publickey = nacl.public.encoding.RawEncoder.decode(self.peer_public_key[to_chat])
                    new_box = Box(self.private_key, peer_publickey)
                    ciphertext = new_box.encrypt(chatmsg)
                    self.send("chat {} {}".format(to_chat, ciphertext))
                elif to_chat == self.current_user:
                    print("Error: Cannot send message to yourself.")
                else:
                    print("Need peer's public key to send the chat message! Please exchange key first")
        elif (cmd[0] == "/upload") or (cmd[0] == "/update"):
            if len(cmd) != 3:
                print("Error: Invalid input")
                return
            #uploadcmd = i.split(' ', 1)
            if self.logged_in == False:
                print("Error: user not logged in")
                return
            des_name = cmd[1]
            filepath = cmd[2]
            print("channel name is %s.\n" % des_name)
            print("filename is %s.." % filepath)
            try:
                fileinfo = os.stat(filepath)
                filesize = fileinfo.st_size
                print ("filesize is %d.\n" % filesize)
                pre_file_msg = "{} {} {} {}".format(cmd[0][1:], des_name, filepath, filesize)
                print(pre_file_msg)
                self.send(pre_file_msg)
                time.sleep(.3)
                try:
                    bytesent = 0
                    with open(filepath) as uploadfile:
                        while bytesent < filesize:
                            remainbytes = filesize - bytesent
                            to_send = BUFFER_SIZE if remainbytes > BUFFER_SIZE else remainbytes
                            sendfile = uploadfile.read(to_send)
                            bytesent += to_send
                            self.send(sendfile)
                except IOError:
                    print("Error: Open file %s failed." % filepath)
                    return
                except OSError as e:
                        print("Socket error: %d." % e.errno)
                        print("%d bytes are sent." % bytesent)
                        return
            except Exception:
                print("Error: unable to open the file %s." % filepath)
                return
        elif (cmd[0] == "/download"):
            if len(cmd) != 3:
                print("Error: Invalid input")
                return
            #uploadcmd = i.split(' ', 1)
            if self.logged_in == False:
                print("Error: User not logged in")
                return
            des_name = cmd[1]
            filepath = cmd[2]
            print("channel name is %s.\n" % des_name)
            print("filename is %s.." % filepath)
            download_msg = "download {} {}".format(des_name, filepath)
            print("download msg is %s" % download_msg)
            self.send(download_msg)
        elif (cmd[0] == "/remove"):
            if len(cmd) != 3:
                print("Error: Invalid input")
                return
            if self.logged_in == False:
                print("Error: User not logged in")
                return
            des_name = cmd[1]
            filepath = cmd[2]
            remove_msg = "remove {} {}".format(des_name, filepath)
            print ("remove msg is %s" % remove_msg)
            self.send(remove_msg)
        elif (cmd[0] == "/getfiles"):
            if len(cmd) != 2:
                print("Error: Invalid input")
                return
            if self.logged_in == False:
                print("Error: User not logged in")
                return
            des_name = cmd[1]
            getfile = "getfiles {}".format(des_name)
            self.send(getfile)
        else:
            #?????
            #self.send("chat {} {}".format(self.current_channel,i))
            print("Error: Invalid cmd input")

    def send(self,msg):
        self.connection.send(msg)

    def loop(self):
        x = RecvLoop(self.connection, self)
        x.start()
        while True:
            i = raw_input('>')
            if i.startswith('/upload') or i.startswith('/update') or i.startswith('/download') or i.startswith('/remove'):
                split = i.split()
                if len(split) != 2:
                    print ("Error: Invalid input")
                else:
                    command = split[0]
                    des_name = split[1]
                    print("Type the name of a file you would like to process:")
                    i = raw_input('>')
                    test = i.split()
                    if len(test) >= 2:
                        print ("Error: Invalid input, filename cannot contain spaces")
                    else:
                        i = "{} {} {}".format(command, des_name, test[0])
            self.handle_input(i)

if (len(sys.argv) == 3):
    client = Client(sys.argv[1],int(sys.argv[2]))
else:
    raise Exception("python textclient.py <server> <port> <-- If running on same machine, <server> is localhost")
