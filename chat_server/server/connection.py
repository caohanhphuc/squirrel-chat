from threading import Thread
from parser import *
from messages import *
import sys
import os

BUFFER_SIZE = 1024

class Connection(Thread):
    """Connections object represent a single client connected to the server"""
    def __init__(self,conn,state):
        Thread.__init__(self)
        self.parser = Parser()
        self.conn = conn
        self.user = None
        self.PACKET_LENGTH = 1024
        self.state = state

    def run(self):
        print("Initiated connection to a client!!!")
        while 1:
            data = self.conn.recv(self.PACKET_LENGTH)
            if data.startswith("exit"):
                print ("connection exit")
                if self.user != None:
                    self.state.exit(self.user)
                self.conn.send("exit")
                return
            cmd_type, parsed_data = self.parser.parse_packet(data)
            if (cmd_type == "register"):
                if self.user != None:
                    self.conn.send("Error: Another user already logged in!\n")
                else:
                    if (parsed_data != None):
                        reg_res = self.state.register(parsed_data.username, parsed_data.password)
                        if (reg_res == 0):
                            self.state.register_observer(parsed_data.username, self.conn)
                            self.user = parsed_data.username
                            self.conn.send("Successfully registered!\n")
                        elif (reg_res == -1):
                            self.conn.send("Error: Username may not start with character #!\n")
                        elif (reg_res == -2):
                            self.conn.send("Error: trying to register an account that already exists!\n")
                        else:
                            self.conn.send("Unlogged error!\n")
                    else:
                        self.conn.send("Error: Please follow the format: register <username> <password>\n")
            elif (cmd_type == "authenticate"):
                if (parsed_data != None):
                    auth_res = self.state.authenticate(parsed_data.username, parsed_data.password)
                    if (auth_res == 0):
                        self.state.register_observer(parsed_data.username, self.conn)
                        self.user = parsed_data.username
                        self.conn.send("User logged in successfully!\n")
                    elif (auth_res == -1):
                        self.conn.send("Error: Incorrect password!\n")
                    elif (auth_res == -2):
                        self.conn.send("Error: No such user is currently registered!\n")
                    elif (auth_res == -3):
                        self.conn.send("Error: User is already logged in!\n")
                    else:
                        self.conn.send("Unlogged error!\n")
                else:
                    self.conn.send("Error: Please follow the format: authenticate <username> <password>\n")
            elif (cmd_type == "update_pw"):
                if (parsed_data != None):
                    if self.user in self.state.loggedin_usernames:
                        self.state.update_pw(self.user, parsed_data.newpassword)
                        self.conn.send("Password updated!\n")
                    else:
                        self.conn.send("User not logged in!\n")
                else:
                    self.conn.send("Error: Please follow the format: update_pw <password>\n")
            elif (cmd_type == "chat"):
                if (parsed_data != None):
                    if (self.user == None):
                        self.conn.send("Error: Need to log in to chat!\n")
                    else:
                        self.state.handle_chat(self.user, parsed_data.user_or_channel, parsed_data.message)
                else:
                    self.conn.send("Error: Please follow the format: chat <user_or_channel> <message>\n")                   
            elif (cmd_type == "join"):
                if (parsed_data != None):
                    if (self.user == None):
                        self.conn.send("Error: Need to log in to join a channel!\n")
                    else:
                        self.state.join(self.user, parsed_data.channel)
                else:
                    self.conn.send("Error: Please follow the format: join <channel_name>\n")
            elif (cmd_type == "gettopic"):
                if (parsed_data != None):
                    if (self.user == None):
                        self.conn.send("Error: Need to log in to get channel topic!\n")
                    else:
                        self.state.gettopic(self.user, parsed_data.channel)
                else:
                    self.conn.send("Error: Please follow the format: gettopic <channel_name>\n")
            elif (cmd_type == "settopic"):
                if (parsed_data != None):
                    if (self.user == None):
                        self.conn.send("Error: Need to log in to reset channel topic!\n")
                    else: 
                        self.state.settopic(self.user, parsed_data.channel, parsed_data.topic)
                else: 
                    self.conn.send("Error: Please follow the format: settopic <channel_name> <topic>\n")
            elif (cmd_type == "leave"):
                if (parsed_data != None):
                    if (self.user == None):
                        self.conn.send("Error: Need to log in to leave channel!\n")
                    else:
                        self.state.leave(self.user, parsed_data.channel)
                else:
                    self.conn.send("Error: Please follow the format: leave <channel_name>\n")
            elif (cmd_type == "ban"):
                if (parsed_data != None):
                    if (self.user == None):
                        self.conn.send("Error: Need to log in to ban users from channel!\n")
                    else:
                        self.state.ban(self.user, parsed_data.banneduser, parsed_data.channel)
                else:
                    self.conn.send("Error: Please follow the format: ban <channel> <user>\n")
            elif (cmd_type == "unban"):
                if (parsed_data != None):
                    if (self.user == None):
                        self.conn.send("Error: Need to log in to unban users form channel!\n")
                    else:
                        self.state.unban(self.user, parsed_data.banneduser, parsed_data.channel)
                else:
                    self.conn.send("Error: Please follow the format: unban <channel> <user>\n")
            elif (cmd_type == "block"):
                if (parsed_data != None):
                    if (self.user == None):
                        self.conn.send("Error: Need to log in to block users!\n")
                    else:
                        self.state.block(self.user, parsed_data.blockeduser)
                else:
                    self.conn.send("Error: Please follow the formate: block <user>\n")
            elif (cmd_type == "exchangekey"):
                if parsed_data != None:
                    if self.user == None:
                        self.conn.send("Error: User not logged in\n")
                    else:
                        self.state.exchangekey(parsed_data.fromuser, parsed_data.touser, parsed_data.key)
                else:
                    self.conn.send("Error: Cannot parse packet!\n")
            elif (cmd_type == "upload"):
                if parsed_data != None:
                    if self.user == None:
                        self.conn.send("Error: User not logged in\n")
                    else:
                        des_name = parsed_data.destination
                        filename = parsed_data.filepath
                        filepath = "{}/{}".format(des_name, filename)
                        filesize = parsed_data.filesize
                        self.state.upload_file(self.user, des_name, filepath, filesize)
            elif (cmd_type == "update"):
                if parsed_data != None:
                    if self.user == None:
                        self.conn.send("Error: User not logged in\n")
                    else:
                        des_name = parsed_data.destination
                        filename = parsed_data.filepath
                        filepath = "{}/{}".format(des_name, filename)
                        filesize = parsed_data.filesize
                        self.state.update_file(self.user, des_name, filepath, filesize)
                else:
                    self.conn.send("Error: Cannot parse packet!\n")
            elif (cmd_type == "download"):
                if parsed_data != None:
                    if self.user == None:
                        self.conn.send("Error: User not logged in\n")
                    else:
                        des_name = parsed_data.destination
                        filename = parsed_data.filepath
                        filepath = "{}/{}".format(des_name, filename)
                        self.state.download_file(self.user, des_name, filepath, 0)
                else:
                    self.conn.send("Error: Cannot parse packet!\n")
            elif (cmd_type == "remove"):
                if parsed_data != None:
                    if self.user == None:
                        self.conn.send("Error: User not logged in\n")
                    else:
                        des_name = parsed_data.destination
                        filename = parsed_data.filepath
                        filepath = "{}/{}".format(des_name, filename)
                        self.state.remove_file(self.user, des_name, filepath)
                else:
                    self.conn.send("Error: Cannot parse packet!\n")
            elif (cmd_type == "getfiles"):
                if parsed_data != None:
                    if self.user == None:
                        self.conn.send("Error: User not logged in\n")
                    else:
                        des_name = parsed_data.destination
                        self.state.get_files(self.user, des_name)
                else:
                    self.conn.send("Error: Cannot parse packet!\n")            

            else:
                self.conn.send("Error: Cannot parse packet!\n")
            
