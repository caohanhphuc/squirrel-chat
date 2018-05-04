#!/usr/bin/env python
from user import *
from channel import *
from messages import *
from jinja2 import utils
import sqlite3
import csv
import sys
import bcrypt
import time
import os
import random
import struct
from Crypto.Cipher import AES
import shutil
import base64
import keyconfig 
import requests
from bcrypt import hashpw, gensalt 
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

DATABASE_PATH = os.path.join(os.path.dirname(__file__), '../../database.db')
BUFFER_SIZE = 1024

def connect_db():
    return sqlite3.connect(DATABASE_PATH)


# 'encrypt_file' and 'decrypt_file' function referrence: 
# https://eli.thegreenplace.net/2010/06/25/aes-encryption-of-files-in-python-with-pycrypto
def encrypt_file(key, in_filename, chunksize = BUFFER_SIZE):
    out_filename = in_filename + '.crypt'
    iv = ''.join(chr(random.randint(0, 0xFF)) for i in range(16))
    encryptor = AES.new(key, AES.MODE_CBC, iv)
    filesize = os.path.getsize(in_filename)
    with open(in_filename, 'rb') as infile:
        with open(out_filename, 'wb') as outfile:
            outfile.write(struct.pack('<Q', filesize))
            outfile.write(iv)
            
            while True:
                chunk = infile.read(chunksize)
                if len(chunk) == 0:
                    break
                elif len(chunk) % 16 != 0:
                    chunk += ' ' * (16 - len(chunk) % 16)
                outfile.write(encryptor.encrypt(chunk))
                    
    return out_filename
                
def decrypt_file(key, username, in_filename, chunksize=BUFFER_SIZE):
    files = in_filename[:len(in_filename) - len(".crypt")].split("/")
    single_filename = files[len(files)-1]
    out_filename = username + "/" + single_filename
    dirs = out_filename.split("/")
    dir_num = 0
    if out_filename.endswith("/"):
        dir_num = len(dirs)
    else:
        dir_num = len(dirs) - 1
    cwd = os.getcwd()
    count = 0
    while (count < dir_num):
        if not os.path.exists(dirs[count]):
            os.makedirs(dirs[count])
        os.chdir(dirs[count])
        count += 1
    os.chdir(cwd)
    
    with open(in_filename, 'rb') as infile:
        origsize = struct.unpack('<Q', infile.read(struct.calcsize('Q')))[0]
        iv = infile.read(16)
        decryptor = AES.new(key, AES.MODE_CBC, iv)
        with open(out_filename, 'wb') as outfile:
            while True:
                chunk = infile.read(chunksize)
                if len(chunk) == 0:
                    break
                outfile.write(decryptor.decrypt(chunk))

            outfile.truncate(origsize)
        return out_filename
            

def generate_key():
    password = b'%#$_9Gjns{]'
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))
    f = Fernet(key)
    return f

class State:
    """"Class for managing the global state of the server"""
    def __init__(self, password_db):
        self.users = {} # No current users
        self.channels = {} # No current channels
        self.loggedin_usernames = []
        self.connections = {} # Map from usernames to Connection objects
        self.password_db = password_db
        self.parse_pwd_db()
        self.file_key = b'&%#$_9Gjns{]H6s_'

    #added self
    def extract_key(self, key_file):
        with open(key_file, "r") as file:
                key = file.readline()
        #eliminate the newline character
        key = key[0:len(key)]
        return key

    def parse_pwd_db(self):
        linenum = 1
        with open(self.password_db, 'rb') as csvfile:
            lines = csv.reader(csvfile, delimiter='\n')
            for line in lines:
                if len(line) > 0 and linenum > 1:
                    try:
                        username, password = line[0].split(",")
                        self.users[username] = User(username, password, list())
                    except ValueError as e:
                        print("Password database has the wrong format!\n")
                        sys.exit(0)
                linenum += 1

    def update_pwd_db(self):
        linenum = 1
        with open(self.password_db, 'wb') as csvfile:
            for key, val in self.users.items():
                if linenum == 1:
                    csvfile.write("username,password\n")
                row = "".join((key, ",", val.password, "\n"))
                csvfile.write(row)
                linenum += 1


    def register(self,username,password):
        """Register a new user with a specified username and password."""
        # Can't add a user to the set of users that's already there..
        if (username[0] == '#'):
            return -1
        else:
            if username not in self.users:
                encryptedpw = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
                u = User(username, encryptedpw,[])
                self.users[username] = u
                self.loggedin_usernames.append(username)
                self.update_pwd_db()
                conn = connect_db()
                cur = conn.cursor()
                try:
                    cur.execute('INSERT INTO `user` VALUES(NULL,?,?, 0, NULL, NULL, NULL, NULL, NULL)', (username, encryptedpw))
                    conn.commit()
                    conn.close()
                    return 0
                except sqlite3.IntegrityError:
                    conn.commit()
                    conn.close()
                    return -2
            else:
                return -2

    def register_observer(self,username,connection):
        """Add a connection object to the list of observers"""
        self.connections[username] = connection

#changed 
    def authenticate(self,username,password):
        """Log in a user that's already registered"""
        if username not in self.loggedin_usernames:
            #if username in self.users:
            conn = connect_db()
            cur = conn.cursor()
            print("here")
            try: 
                cur.execute('SELECT password FROM `user` WHERE username=?', (username,))
                row = cur.fetchone()
                print(row[0])
                if row is not None: 
                    if row[0] is not None:
                        print(row[0])
                        if username not in self.users:
                            self.users[username] = User(username, row[0], list())
                        #u = self.users[username]
                        if bcrypt.checkpw(password, row[0].encode()):
                            # Log in the user
                            self.loggedin_usernames.append(username)
                            conn.commit()
                            conn.close()
                            return 0
                        else:
                            conn.commit()
                            conn.close()
                            return -1
                    else:
                        conn.commit()
                        conn.close()
                        return -1
                else:
                    conn.commit()
                    conn.close()
                    return -2
            except sqlite3.IntegrityError:
                conn.commit()
                conn.close()
                return -1
                
            #else:
                #return -2
        else:
            return -3

    def notify(self,username,msg):
        """Notify the user of a certain message"""
        self.connections[username].send(msg)

    def update_pw(self, username, password):
        #update password given username and password; user logged in
        encrypted_newpw = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
        self.users[username].password = encrypted_newpw
        self.update_pwd_db()
        conn = connect_db()
        cur = conn.cursor()
        try:
            cur.execute('UPDATE `user` SET password=? WHERE username=?', (encrypted_newpw, username))            
            conn.commit()
            conn.close()
        except sqlite3.IntegrityError:
            conn.commit()
            conn.close()


    def handle_chat(self,fromuser,to,message):
        """Perform the work to notify each user associated with a given channel or private message"""
        if to.startswith("#"):
            if to in self.channels:
                chan = self.channels[to]
                if fromuser in chan.members:
                    for user in chan.members:
                        '''
                        if fromuser == user:
                            #continue
                        '''
                        '''
                        print(user)
                        print(fromuser)
                        conn = connect_db()
                        cur = conn.cursor()
                        cur.execute('SELECT blocked FROM `user`WHERE username=?', (user,))
                        row = cur.fetchone()
                        if row is not None:
                            if row[0] is not None:
                                blocklist = row[0].split(';')
                                if fromuser not in blocklist:
                                    msg = ChatFromMessage(fromuser,to,message)
                        if fromuser in self.users[user.encode()].blocklist:
                            #self.notify(fromuser, "Blocked from sending messages to %s.\n" % (user))
                            print("User is blocked from this channel")
                        else:
                            msg = ChatFromMessage(fromuser,to,message)
                            #self.notify(user, msg.render())
                    '''
                    #write to log
                    msg_log = fromuser + "> " + message + "\n"
                    print("msg log %s" % msg_log)
                    print("count is %d" %self.channels[to].msg_count)
                    #if (self.channels[to].msg_count >= 2):
                    print("count is %d" %self.channels[to].msg_count)
                    self.write_log(to, msg_log)
                    self.channels[to].current_log = self.channels[to].current_log + msg_log
                    #self.channels[to].msg_count += 1
                    
                else:
                    self.notify(fromuser, "Error: Not a member of channel!\n")
            else:
                self.notify(fromuser, "Error: Channel does not exist!\n")
        else:
            if to in self.loggedin_usernames:
                if (to == fromuser):
                    self.notify(to, "Error: Cannot send a message to yourself!\n")
                else:
                    if fromuser in self.users[to].blocklist:
                        self.notify(fromuser, "Error: Blocked from sending messages to target user!\n")
                    else:
                        msg = ChatFromMessage(fromuser, to, message)
                        self.notify(to, msg.render())
            else:
                self.notify(fromuser, "Error: Target user is not logged in or does not exist\n")

    def write_log(self, channel, msg_log):
        timestamp = str(int(round(time.time() * 1000)))
        log_name = "logs/log-" + channel[1:] + "-" + timestamp + ".log"
        #Fernet
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
                        algorithm=hashes.SHA256(),
                        length=32,
                        salt=salt,
                        iterations=100000,
                        backend=default_backend()
                        )
        key = base64.urlsafe_b64encode(kdf.derive(keyconfig.part3_password.encode()))
        fernet = Fernet(key)
        #log_str = utils.escape(self.channels[channel].current_log)
        log_str = utils.escape(msg_log)
        encrypted_log = fernet.encrypt(log_str.encode())
        encrypted_info = ""
        with open(log_name, 'wb') as logfile:
            h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
            h.update(log_str.encode())
            mac_str = bytes(h.finalize())
            logfile.write(salt + "\n" + encrypted_log + "\n" + mac_str)
            encrypted_info = salt + "\n" + encrypted_log + "\n" + mac_str
        conn = connect_db()
        cur = conn.cursor()
        conn.text_factory = str
        try:
            print("insertting")
            print(channel)
            print("encrypted info in write into is ")
            print(encrypted_info)
            cur.execute('INSERT INTO `chats` VALUES(NULL, ?, NULL, ?)', (channel, encrypted_info))
            conn.commit()
            conn.close()
        except sqlite3.IntegrityError:
            print("inserting chats failed")
            conn.commit()
            conn.close()
        self.channels[channel].current_log = ""
        self.channels[channel].msg_count = 0

    def add_channel(self, channel_name, topic, admin, memberlist, banlist):
        members = memberlist.split(';')
        print(members)
        bans = None
        if banlist is not None:
            bans = banlist.split(';')
        else:
            bans = list()
        print(bans)
        new_chan = Channel(channel_name, topic, members, admin, bans)
        self.channels[channel_name] = new_chan

    def join(self, user, channel_name):
        if channel_name.startswith("#"):
            conn = connect_db()
            cur = conn.cursor()
            cur.execute('SELECT topics, admins, members, banned FROM `channels` WHERE channelname = ?', (channel_name,))
            row = cur.fetchone()
            print("in joining %s" % channel_name)
            print(row)
            if row is not None:
                self.add_channel(channel_name, row[0], row[1], row[2], row[3])
                if channel_name in self.channels:
                    channel = self.channels[channel_name]
                    if user in channel.banlist:
                        self.notify(user, "Error: User is banned from sending messages to channel!\n")
                    else:
                        if user in channel.members:
                            self.notify(user, "Error: User is already a member of channel.\n")
                        else:
                            channel.members.append(user)
                            cur.execute('SELECT members FROM `channels` where channelname=?', (channel_name,))
                            row = cur.fetchone()
                            newmem = row[0]
                            newmem += ';'
                            newmem += user
                            cur.execute('UPDATE `channels` SET members=? WHERE channelname=?', (newmem, channel_name))
                            # update channels for user
                            cur.execute('SELECT channels FROM `user` where username=?', (user,))
                            rowc = cur.fetchone()
                            channel_list = rowc[0]
                            if channel_list is None:
                                channel_list = channel_name
                            else:
                                channel_list += channel_name
                            cur.execute('UPDATE `user` SET channels=? WHERE username=?', (channel_list, user))
                            conn.commit()
                            conn.close()
                            self.notify(user, "Successfully joined channel!\n")
            else:
                print("here adding channels")
                new_channel = Channel(channel_name, "Default topic", [user], user, [])
                cur.execute('INSERT INTO `channels` VALUES(NULL, ?, ?, ?, ?, NULL, NULL)', (channel_name, user, user, "Default topic"))
                cur.execute('SELECT channels FROM `user` WHERE username= ?', (user,))
                row = cur.fetchone()
                chanlist = ""
                if row[0] is None:
                    chanlist = channel_name
                else:
                    chanlist = row[0] + channel_name
                print("chan list before insertion")
                print(chanlist)
                cur.execute('UPDATE `user` SET channels=? WHERE username= ?', (chanlist, user))
                print("heheupdating ahahhahaha")
                cur.execute('UPDATE `user` SET channeladmin =? WHERE username= ?', (channel_name, user))
                conn.commit()
                conn.close()
                self.channels[channel_name] = new_channel
                self.notify(user, "Channel created!\n")
        else:
            self.notify(user, "Error: Channel name must start with #.\n")
            

    def gettopic(self, user, channel_name):
        if channel_name in self.channels:
            channel = self.channels[channel_name]
            if user in channel.members:
                topic_mess = "".join(("topic ", channel_name, " ", channel.topic))
                self.notify(user, topic_mess)
            else:
                self.notify(user, "Error: Need to join channel to get topic!\n")
        else:
            self.notify(user, "Error: Channel does not exist!\n")

    def settopic(self, user, channel_name, new_topic):
        if channel_name in self.channels:
            channel = self.channels[channel_name]
            conn = connect_db()
            cur = conn.cursor()
            cur.execute('SELECT admins FROM `channels` WHERE channelname=?', (channel_name,))
            row = cur.fetchone()
            adminlist = row[0].split(';')
            conn.commit()
            conn.close()
            print("admin list is")
            print(adminlist)
            channel.admin = adminlist
            if user in channel.admin:
                channel.topic = new_topic
                conn = connect_db()
                cur = conn.cursor()
                cur.execute('UPDATE `channels` SET topics=? WHERE channelname=?', (new_topic, channel_name))
                conn.commit()
                conn.close()
                self.notify(user, "Topic reset!\n")
            else:
                self.notify(user, "Error: Not permitted to reset channel topic!\n")
        else:
            self.notify(user, "Error: Channel does not exist!\n")

    def leave(self, user, channel_name):
        if channel_name in self.channels:
            channel = self.channels[channel_name]
            if user in channel.members:
                channel.members.remove(user)
                self.notify(user, "Successfully left channel!\n")
            else:
                self.notify(user, "Error: Not a member of channel!\n")
        else:
            self.notify(user, "Error: Channel does not exist!\n")

    def ban(self, user, banned_user, channel_name):
        if channel_name in self.channels:
            channel = self.channels[channel_name]
            conn = connect_db()
            cur = conn.cursor()
            cur.execute('SELECT admins FROM `channels` WHERE channelname=?', (channel_name,))
            row = cur.fetchone()
            adminlist = row[0].split(';')
            conn.commit()
            conn.close()
            print("admin list is")
            print(adminlist)
            channel.admin = adminlist
            if user in channel.admin:
                if banned_user in self.users:
                    conn = connect_db()
                    cur = conn.cursor()
                    if banned_user in channel.banlist:
                        self.notify(user, "Error: User already banned!\n")
                    else:
                        channel.banlist.append(banned_user)
                        try:
                            #update banned in channels
                            cur.execute('SELECT banned FROM `channels` WHERE channelname = ?', (channel_name,))
                            row = cur.fetchone()
                            banlist = ""
                            if row[0] is None:
                               banlist = banned_user
                            else:
                                banlist = row[0] + ';' + banned_user
                            cur.execute('UPDATE `channels` SET banned = ? WHERE channelname=?', (banlist, channel_name))
                            #update banned in user
                            cur.execute('SELECT banned FROM `user` WHERE username = ?', (banned_user,))
                            row2 = cur.fetchone()
                            bannedlist = ""
                            if row2[0] is None:
                               bannedlist = channel_name
                            else:
                                bannedlist = row2[0] + channel_name
                            cur.execute('UPDATE `user` SET banned = ? WHERE username=?', (bannedlist, banned_user))
                            self.notify(user, "Successfully blocked user!\n")
                        except sqlite3.IntegrityError:
                            self.notify(user, "Blocking target failed\n")
                    if banned_user in channel.members:
                        channel.members.remove(banned_user)
                        cur.execute('SELECT members FROM `channels` WHERE channelname = ?', (channel_name,))
                        mem = cur.fetchone()
                        members = ""
                        if mem[0] is not None:
                            mem_list = members.split(';')
                            for m in mem_list:
                                if m != banned_user and len(m) != 0:
                                    members = members + m + ';'
                        print("new member list of channel %s is" % channel_name)
                        print(members)
                        cur.execute('UPDATE `channels` SET members = ? WHERE channelname=?', (members, channel_name))
                    conn.commit()
                    conn.close()
                else:
                    self.notify(user, "Error: User does not exist!\n")
            else:
                self.notify(user, "Error: Not permitted to ban users from channel!\n")
        else:
            self.notify(user, "Error: Channel does not exist!\n")

    def unban(self, user, banned_user, channel_name):
        if channel_name in self.channels:
            channel = self.channels[channel_name]
            conn = connect_db()
            cur = conn.cursor()
            cur.execute('SELECT admins FROM `channels` WHERE channelname=?', (channel_name))
            row = cur.fetchone()
            adminlist = row[0].split(';')
            conn.commit()
            conn.close()
            print("admin list is")
            print(adminlist)
            channel.admin = adminlist
            if user in channel.admin:
                if banned_user in self.users:
                    if banned_user in channel.banlist:
                        channel.banlist.remove(banned_user)
                        conn = connect_db()
                        cur = conn.cursor()
                        cur.execute('SELECT banned FROM `channels` WHERE channelname = ?', (channel_name,))
                        ban = cur.fetchone()
                        newban = ""
                        if ban[0] is not None:
                            ban_list = ban.split(';')
                            for b in ban_list:
                                if b != banned_user:
                                    newban = newban + b + ';'
                        print("new ban list of channel %s is" % channel_name)
                        print(newban)
                        cur.execute('UPDATE `channels` SET banned = ? WHERE channel_name=?', (newban, channel_name))
                        self.notify(user, "Successfully unbanned user from channel!\n")
                    else:
                        self.notify(user, "Error: User is not in banned list!\n")
                else:
                    self.notify(user, "Error: User does not exist!\n")
            else:
                self.notify(user, "Error: Not permitted to unban users from channel!\n")
        else:
            self.notify(user, "Error: Channel does not exist!\n")

    def block(self, user, blocked_user):
        if blocked_user in self.users:
            u = self.users[user]
            if blocked_user in u.blocklist:
                self.notify(user, "Error: User already blocked!\n")
            else:
                u.blocklist.append(blocked_user)
                print(u.blocklist)
                conn = connect_db()
                cur = conn.cursor()
                try:
                    cur.execute('SELECT blocked FROM `user` WHERE username = ?', (user,))
                    row = cur.fetchone()
                    blockedlist = ""
                    if row[0] is None:
                        blockedlist = blocked_user
                    else:
                        blockedlist = row[0] + ';' + blocked_user
                    cur.execute('UPDATE `user` SET blocked = ? WHERE username=?', (blockedlist, user))
                    conn.commit()
                    conn.close()
                    self.notify(user, "Successfully blocked user!\n")
                except sqlite3.IntegrityError:
                    self.notify(user, "Blocking target failed\n")
        else:
            self.notify(user, "Error: Target user does not exist!\n")

    def exit(self, user):
        self.loggedin_usernames.remove(user)


    def server_exit(self):
        for key, val in self.channels.items():
            if val.msg_count > 0:
               self.write_log(key)

    def exchangekey(self, fromuser, touser, key):
        if touser in self.users:
            if touser in self.loggedin_usernames:
                msg = ExchangeKey(fromuser, touser, key).render()
                self.notify(touser, msg)
            else:
                self.notify(fromuser, "Error: Target user not logged in\n")
        else:
            self.notify(fromuser, "Error: Target user does not exist!\n")

    def cleanup_file(self, username, bytes_received, filesize):
        received = bytes_received
        try: 
            while received < filesize:
                remainbytes = filesize - received
                bytes_to_get = BUFFER_SIZE if remainbytes > BUFFER_SIZE else remainbytes
                connection = self.connections[username]
                connection.recv(bytes_to_get)
                received += bytes_to_get
        except OSError as e:
            print("Socket error: %d." % e.errno)
            return
    
    def upload_file(self, username, des_name, filepath, filesize):
        if des_name.startswith("#"):
            if des_name not in self.channels:
                self.notify(username, "Error: channel {} does not exist!\n".format(des_name))
                self.cleanup_file(username, 0, filesize)
                return
        else:
            if des_name not in self.users:
                self.notify(username, "Error: user {} does not exist!\n".format(des_name))
                self.cleanup_file(username, 0, filesize)
                return
            else:
                if des_name not in self.loggedin_usernames:
                    self.notify(username, "Error: user {} is not logged in!\n".format(des_name))
                    self.cleanup_file(username, 0, filesize)
                    return
        # save files locally for now
        dirs = filepath.split("/")
        dir_num = 0
        if filepath.endswith("/"):
            dir_num = len(dirs)
        else:
            dir_num = len(dirs) - 1
        cwd = os.getcwd()
        count = 0
        while (count < dir_num):
            if not os.path.exists(dirs[count]):
                os.makedirs(dirs[count])
            os.chdir(dirs[count])
            count += 1
        os.chdir(cwd)
        received = 0
        try:
            with open(filepath, 'wb+') as write_file:
                self_conn = self.connections[username]
                while received < filesize:
                    remainbytes = filesize - received
                    bytes_to_get = BUFFER_SIZE if remainbytes > BUFFER_SIZE else remainbytes
                    getfile = self_conn.recv(bytes_to_get)
                    received += bytes_to_get
                    write_file.write(getfile)       
            write_file.close()
        except IOError:
            self.notify(username, "Error: (in post state)Open file {} failed.\n".format(filepath))
            self.cleanup_file(username, received, filesize)
        outpath = ""
        try:
            outpath = encrypt_file(self.file_key, filepath)
            #POST to Tiny Web Server
            try:
                file_to_post = {'file': open(outpath, 'rb')}
                try:
                    post_req = requests.post("http://localhost:8080/" + outpath, files=file_to_post)
                    if (post_req.ok):
                        shutil.rmtree(des_name)
                        if des_name.startswith("#"):
                            self.channels[des_name].upload_dict[filepath] = username
                    else:
                        print("Error: Failed to post file to Tiny Web Server!")
                        print(post_req.status_code)
                        sys.exit(1)
                except Exception as e:
                    print("Error: post request in 'upload' failed")
                    print(e)
            except Exception as e:
                print("Error: opening file %s in 'upload' failed" % outpath)
                print(e)
            except OSError as e:
                print("Socket error: %d." % e.errno)
                return
        except Exception as e:
            print("Error: encrypting file in 'upload' failed")
            print(e)
            return

    def update_file(self, username, des_name, filepath, filesize):
        if des_name.startswith("#"):
            if des_name not in self.channels:
                self.notify(username, "Error: channel {} does not exist!\n".format(des_name))
                self.cleanup_file(username, 0, filesize)
                return
            if username != self.channels[des_name].admin and username != self.channels[des_name].upload_dict[filepath]:
                self.notify(username, "Error: not authorized to update file\n")
                self.cleanup_file(username, 0, filesize)
                return
        else:
            if des_name not in self.users:
                self.notify(username, "Error: user {} does not exist!\n".format(des_name))
                self.cleanup_file(username, 0, filesize)
                return
            else:
                if des_name not in self.loggedin_usernames:
                    self.notify(username, "Error: user {} is not logged in!\n".format(des_name))
                    self.cleanup_file(username, 0, filesize)
                    return
                if des_name != username:
                    self.notify(username, "Error: not authorized to update file\n")
                    self.cleanup_file(username, 0, filesize)
                    return
        # save files locally for now
        dirs = filepath.split("/")
        dir_num = 0
        if filepath.endswith("/"):
            dir_num = len(dirs)
        else:
            dir_num = len(dirs) - 1
        cwd = os.getcwd()
        count = 0
        while (count < dir_num):
            if not os.path.exists(dirs[count]):
                os.makedirs(dirs[count])
            os.chdir(dirs[count])
            count += 1
        os.chdir(cwd)
        received = 0
        try:
            with open(filepath, 'wb+') as write_file:
                self_conn = self.connections[username]
                while received < filesize:
                    remainbytes = filesize - received
                    bytes_to_get = BUFFER_SIZE if remainbytes > BUFFER_SIZE else remainbytes
                    getfile = self_conn.recv(bytes_to_get)
                    received += bytes_to_get
                    write_file.write(getfile)       
            write_file.close()
        except IOError:
            self.notify(username, "Error: Open file in 'update' {} failed.\n".format(filepath))
            self.cleanup_file(username, received, filesize)
        outpath = ""
        try:
            outpath = encrypt_file(self.file_key, filepath)
            #POST to Tiny Web Server
            try:
                file_to_post = {'file': open(outpath, 'rb')}
                
                try:
                    put_req = requests.put("http://localhost:8080/" + outpath, files=file_to_post)
                    if (put_req.ok):
                        print("Put file to Tiny Web Server!")
                        #delete original file on Squirrel server                      
                        shutil.rmtree(des_name)
                    else:
                        print("Error: Failed to put file to Tiny Web Server!")
                        print(put_req.status_code)
                        sys.exit(1)
                except Exception as e:
                    print("Error: Put request failed")
                    print(e)
            except Exception as e:
                print("Error: opening file %s in update failed" % outpath)
                print(e)
            except OSError as e:
                print("Socket error: %d." % e.errno)
                return
        except Exception as e:
            print("Error: encrypting file in 'update' failed")
            print(e)
            return

    def download_file(self, username, des_name, filepath, filesize):
        if des_name.startswith("#"):
            if des_name not in self.channels:
                self.notify(username, "Error: channel {} does not exist!\n".format(des_name))
                self.cleanup_file(username, 0, filesize)
                return
        else:
            if des_name not in self.users:
                self.notify(username, "Error: user {} does not exist!\n".format(des_name))
                self.cleanup_file(username, 0, filesize)
                return
            else:
                if des_name not in self.loggedin_usernames:
                    self.notify(username, "Error: user {} is not logged in!\n".format(des_name))
                    self.cleanup_file(username, 0, filesize)
                    return
        try:
            #GET to Tiny Web Server
            outputfile = filepath
            filepath += ".crypt"
            dirs = outputfile.split("/")
            dir_num = 0
            if outputfile.endswith("/"):
                dir_num = len(dirs)
            else:
                dir_num = len(dirs) - 1
            cwd = os.getcwd()
            count = 0
            while (count < dir_num):
                if not os.path.exists(dirs[count]):
                    os.makedirs(dirs[count])
                os.chdir(dirs[count])
                count += 1
            os.chdir(cwd)

            get_req = requests.get("http://localhost:8080/" + filepath)
            if (get_req.ok):
                try:
                    print("Got file from Tiny Web Server!")
                    with open(filepath, 'wb') as in_file:
                        for chunk in get_req.iter_content(chunk_size=BUFFER_SIZE):
                            in_file.write(chunk)
                    try:
                        outfile = decrypt_file(self.file_key, username, filepath)
                        filesize = os.path.getsize(outfile)
                        download_msg = "file {} {} {}".format(des_name, outfile, filesize)
                        self.notify(username, download_msg)
                        time.sleep(.3)
                        try:
                            with open(outfile, 'rb') as outfile:
                                while True:
                                    chunk = outfile.read(BUFFER_SIZE)
                                    if len(chunk) == 0:
                                        break
                                    self.notify(username, chunk)
                            shutil.rmtree(des_name)
                        except IOError as e:
                            print ("Error: sending decrypted file in download failed")
                            return
                    except Exception as e:
                        print("Error: decryption file failed in download")
                        return
                    
                except IOError as e:
                    print("Error: read in file from stream in download failed")
                    print(e)
                    return
            else:
                print("Error: Failed to get file from Tiny Web Server!")
                sys.exit(1)
        except IOError:
            print("Error: Open file %s failed." % filepath)
            return
        except OSError as e:
            print("Socket error: %d." % e.errno)
            return

    def remove_file(self, username, des_name, filepath):
        if des_name.startswith("#"):
            if des_name not in self.channels:
                self.notify(username, "Error: channel {} does not exist!\n".format(des_name))
                return
            if username != self.channels[des_name].admin and username != self.channels[des_name].upload_dict[filepath]:
                self.notify(username, "Error: not authorized to update file\n")
                return
            #need to check whether the username == uploader 
        else:
            if des_name not in self.users:
                self.notify(username, "Error: user {} does not exist!\n".format(des_name))
                return
            else:
                if des_name not in self.loggedin_usernames:
                    self.notify(username, "Error: user {} is not logged in!\n".format(des_name))
                    return
                if des_name != username:
                    self.notify(username, "Error: not authorized to update file\n")
                    return
        filepath += '.crypt'
        split = filepath.split('/')
        filename = split[len(split) - 1]
        filedir = filepath[:len(filepath) - len(filename) - 1]
        delete_req = requests.delete("http://localhost:8080/" + filepath)
        if (delete_req.ok):
            print("Deleted file from Tiny Web Server!")
        else:
            print("Error: Failed to delete file from Tiny Web Server!")
            sys.exit(1)
    
    def get_files(self, username, des_name):
        if des_name.startswith("#"):
            if des_name not in self.channels:
                self.notify(username, "Error: channel {} does not exist!\n".format(des_name))
                return
        else:
            if des_name not in self.users:
                self.notify(username, "Error: user {} does not exist!\n".format(des_name))
                return
            else:
                if des_name not in self.loggedin_usernames:
                    self.notify(username, "Error: user {} is not logged in!\n".format(des_name))
                    return
        get_req = requests.get("http://localhost:8080/" + des_name)
        if (get_req.ok):
            print("Got file list from Tiny Web Server!")
            #send data back to client
            for chunk in get_req.iter_content(chunk_size=BUFFER_SIZE):
                self.notify(username, chunk)
        else:
            print("Error: Failed to get file from Tiny Web Server!")
            sys.exit(1)
