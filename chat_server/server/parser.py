from messages import *

class Parser():
    """Parser for messages sent via the SquirrelChat protocol"""
    def __init__(self):
        self.current_input = ""

    # Parse a simple packet
    def parse_packet(self,data):
        string = data
        #.decode("utf-8")
        split = string.split()
        if (len(split) > 0):
            if split[0] == "authenticate":
                if (len(split) == 3):
                    return ("authenticate", AuthenticateMessage(split[1],split[2]))
                return ("authenticate", None)
            elif split[0] == "register":
                if (len(split) == 3):
                    return ("register", RegisterMessage(split[1],split[2]))
                return ("register", None)
            elif split[0] == "update_pw":
                if (len(split) == 2):
                    return("update_pw", UpdatePasswordMessage(split[1]))
                return("update_pw", None)
            elif split[0] == "chat":
                msg = string.split(' ', 2)
                if (len(msg) == 3):
                    return ("chat", ChatMessage(msg[1],msg[2]))
                return("chat", None)
            elif split[0] == "error":
                msg = string.split(' ', 1)
                return ("error", ErrorMessage(msg[1]))
            elif split[0] == "join":
                if (len(split) == 2):
                    return ("join", JoinMessage(split[1]))
                return("join", None)
            elif split[0] == "gettopic":
                if (len(split) == 2):
                    return ("gettopic", GetTopicMessage(split[1]))
                return("gettopic", None)
            elif split[0] == "settopic":
                msg = string.split(' ', 2)
                if (len(msg) == 3):
                    return("settopic", SetTopicMessage(msg[1], msg[2]))
                return("settopic", None)
            elif split[0] == "leave":
                if (len(split) == 2):
                    return("leave", LeaveMessage(split[1]))
                return("leave", None)
            elif split[0] == "ban":
                if (len(split) == 3):
                    return("ban", BanMessage(split[1], split[2]))
                return("ban", None)
            elif split[0] == "unban":
                if (len(split) == 3):
                    return("unban", UnbanMessage(split[1], split[2]))
                return("unban", None)
            elif split[0] == "block":
                if (len(split) == 2):
                    return("block", BlockMessage(split[1]))
                return("block", None)
            elif split[0] == "topic":
                if (len(split) == 3):
                    return("topic", TopicMessage(split[1], split[2]))
                return("topic", None)
            elif split[0] == "exit":
                return("exit", None)
            elif split[0] == "exchangekey":
                exchange = string.split(' ', 3)
                if (len(exchange) == 4):
                    return ("exchangekey", ExchangeKey(exchange[1], exchange[2], exchange[3]))
                return ("exchangeKey", None)
            elif split[0] == "upload":
                print("parsing upload......")
                uploadfile = string.split(' ', 3)
                if len(uploadfile) == 4:
                    return ("upload", ProcessFile(uploadfile[1], uploadfile[2], int(uploadfile[3]))) 
                return ("upload", None)
            elif split[0] == "update":
                print("parsing update......")
                uploadfile = string.split(' ', 3)
                if len(uploadfile) == 4:
                    return ("update", ProcessFile(uploadfile[1], uploadfile[2], int(uploadfile[3]))) 
                return ("update", None)
            elif split[0] == "download":
                print("parsing download")
                fileinfo = string.split(' ', 2)
                if len(fileinfo) == 3:
                    return ("download", ProcessFile(fileinfo[1], fileinfo[2], None))
                return ("download", None)
            elif split[0] == "remove":
                removeinfo = string.split(' ', 2)
                if len(removeinfo) == 3:
                    return ("remove", ProcessFile(removeinfo[1], removeinfo[2], None))
                return ("remove", None)
            elif split[0] == "getfiles":
                getfileinfo = string.split(' ', 1)
                if len(getfileinfo) == 2:
                    return ("getfiles", ProcessFile(getfileinfo[1], None, None))
                return ("getfiles", None)
            else:
                return("", None)
        else:
            return("", None)
