from connection import *
from socket import *
from state import *
import sys
import ssl
import os

CERT = '../cert.pem'
KEY = '../key.pem'

class Server:
    """Toplevel server implementation"""
    def run(self):
        try: 
            s = socket(AF_INET, SOCK_STREAM)
            s.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
            s.bind((gethostbyname("localhost"),self.port))
            s.listen(5)
            while True:
                print("Waiting for new connections..")
                #clconn = None
                (client,address) = s.accept()
                try:
                    #clconn = context.wrap_socket(client, server_side=True)
                    secured_client = ssl.wrap_socket(client, server_side=True, certfile=CERT, keyfile=KEY)
                    connection = Connection(secured_client, self.state)
                    print("Running thread for connection..")
                    connection.start()
                except ssl.SSLError as e:
                    print(e)
        except KeyboardInterrupt:
            self.state.server_exit()
            try:
                sys.exit(0)
            except SystemExit:
                os._exit(0)
            

    def __init__(self,port,pwd_db):
        self.port = port
        self.state = State(pwd_db)
        self.password_db = pwd_db

# Main code entry: build a server and start it
if (len(sys.argv) < 2):
	print("Passwords database missing!")
	sys.exit(0)

s = Server(4000, sys.argv[1])
s.run()
