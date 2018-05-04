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

def test_settopic():
    #Test that only the admin can change the topic using settopic
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
        raise "Client 1 cannot connect to server!"
        sys.exit(0)
    if sock_two == None:
        raise "Client 2 cannot connect to server!"
    
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

    #sock_one is admin
    sock_one.send("join #testchannel".encode())
    try:
        join_output = sock_one.recv(SIZE)
        assert ("error" not in string.strip(join_output).lower()), "join error!"
    except socket.timeout, e:
        pass
    
    sock_two.send("join #testchannel".encode())
    try:
        join_output = sock_two.recv(SIZE)
        assert ("error" not in string.strip(join_output).lower()), "join error!"
    except socket.timeout, e:
        pass

    sock_two.send("settopic #testchannel this is gonna fail".encode())
    try:
        settopic_output = sock_two.recv(SIZE)
        assert ("error" in string.strip(settopic_output).lower()), "settopic error!"
    except socket.timeout, e:
        assert True, "settopic error!"

    sock_two.send("gettopic #testchannel".encode())
    try:
        gettopic_output = sock_two.recv(SIZE)
        assert (string.strip(gettopic_output) != "topic #testchannel this is gonna fail") , "gettopic error!"
    except socket.timeout, e:
        assert True, "gettopic error!"

    sock_one.send("settopic #testchannel test topic".encode())
    try:
        settopic_output = sock_one.recv(SIZE)
        assert ("error" not in string.strip(settopic_output).lower()), "settopic error!"
    except socket.timeout, e:
        pass

    sock_one.send("gettopic #testchannel".encode())
    try:
        final_output = sock_one.recv(SIZE)
        assert (string.strip(final_output) == "topic #testchannel test topic") , "gettopic error!"
    except socket.timeout, e:
        assert True, "gettopic error!"

    print("Test settopic passed!")
    cleanup(pid)

test_settopic()
