import os
import socket
import atexit
import signal
import subprocess
import string
from time import sleep
from parser import *
from subprocess import Popen
from channel import *

address = "localhost"
port = 4000
SIZE = 1024
pid = None
p = Parser()

def cleanup(process_id):
    process_id.kill()
    os.system("rm thepasswords.csv 2>err")
    os.system("rm out err 2>err")

def test_block():
    os.system("cp example_passwords.csv thepasswords.csv")
    with open("output", "w") as output:
        with open("error_output", "w") as err_output:
            pid = subprocess.Popen("python server.py thepasswords.csv".split(), stderr = err_output, stdout = output)
    atexit.register(cleanup, pid)
    sleep(.5)
    sock_one = socket.socket()
    sock_one.settimeout(1)
    sock_one.connect((address, port))
    sock_two = socket.socket()
    sock_two.settimeout(1)
    sock_two.connect((address, port))
    if sock_one == None:
        print("Cannot connect to server 1!\n")
        sys.exit(0)
    if sock_two == None:
        print("Cannot connect to server 2!\n")
        sys.exit(0)

    sock_one.send("register u1 p1".encode())
    try:
        register_output = sock_one.recv(SIZE)
        assert ("error" not in string.strip(register_output).lower()), "register error!"
    except socket.timeout, e:
        pass

    sock_two.send("register u2 p2".encode()) 
    try:
        register_output = sock_two.recv(SIZE)
        assert ("error" not in string.strip(register_output).lower()), "register error!"
    except socket.timeout, e:
        pass

    sock_one.send("chat u2 bzbzbz this is a bee".encode())
    try:
        chat_output = sock_two.recv(SIZE)
        assert ("chatfrom u1 u2 bzbzbz this is a bee" == string.strip(chat_output)), "chat error!"
    except socket.timeout, e:
        assert True, "chat error!"
        
    sock_two.send("block u1".encode())
    try:
        block_output = sock_two.recv(SIZE)
        assert ("error" not in string.strip(block_output).lower()), "block error!"
    except socket.timeout, e:
        pass

    sock_one.send("chat u2 bzbz can you hear me??".encode())
    try:
        chat_output = sock_two.recv(SIZE)
        assert ("chatfrom" not in string.strip(chat_output).lower()), "block error!"
    except socket.timeout, e:
        pass        

    print("Test block passed!")
    cleanup(pid)

test_block() 
