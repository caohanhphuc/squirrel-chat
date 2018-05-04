class Message:
    """Abstract base class for representing messages sent to clients"""
    def __init__(self):
        pass
    
    def render(self):
        """Expected to return bytes"""
        pass

class JoinMessage(Message):
    def __init__(self,channel):
        self.channel = channel

    def render(self):
        return ("join {}".format(self.channel))

class UpdatePasswordMessage(Message):
    def __init__(self,newpassword):
        self.newpassword = newpassword

    def render(self):
        return ("updatepassword {}".format(self.newpassword)).encode()

class BlockMessage(Message):
    def __init__(self,user):
        self.blockeduser = user

    def render(self):
        return ("block {}".format(self.blockeduser)).encode()

class BanMessage(Message):
    def __init__(self,channel,user):
        self.banneduser = user
        self.channel = channel

    def render(self):
        return ("ban {} {}".format(self.banneduser,self.channel)).encode()

class UnbanMessage(Message):
    def __init__(self, channel, user):
        self.banneduser = user
        self.channel = channel

    def render(self):
        return ("unban {} {}".format(self.banneduser,self.channel)).encode()

class GetTopicMessage(Message):
    def __init__(self,channel):
        self.channel = channel

    def render(self):
        return ("gettopic {}".format(self.channel))

class SetTopicMessage(Message):
    def __init__(self,channel,topic):
        self.channel = channel
        self.topic = topic

    def render(self):
        return ("settopic {} {}".format(self.channel,self.topic))

class TopicMessage(Message):
    def __init__(self,channel,topic):
        self.channel = channel
        self.topic = topic 

    def render(self):
        return ("topic {} {}".format(self.channel,self.topic)).encode()
    
    def __eq__(self, other):
        return (self.channel == other.channel and self.topic == other.topic)

    def __ne__(self, other):
        return not self.__eq__(other)

class AuthenticateMessage(Message):
    def __init__(self,username,password):
        self.username = username
        self.password = password

    def render(self):
        return ("authenticate {} {}".format(self.username, self.password)).encode()

class RegisterMessage(Message):
    def __init__(self,username,password):
        self.username = username
        self.password = password

    def render(self):
        return ("register {} {}".format(self.username, self.password)).encode()

class ChatMessage(Message):
    def __init__(self,user_or_channel,message):
        self.user_or_channel = user_or_channel
        self.message = message
    
    def render(self):
        m = "chat {} {} {}".format(self.user_or_channel,len(self.message),self.message)
        return m.encode()

class ChatFromMessage(Message):
    """A reply from the server notifying a client that they have received a message from either a user or a channel"""
    def __init__(self,fromuser,user_or_channel,message):
        self.fromuser = fromuser
        self.message = message
        self.user_or_channel = user_or_channel
    
    def render(self):
        m = "chatfrom {} {} {}".format(self.fromuser, self.user_or_channel, self.message)
        return m
        #return m.encode()

class ErrorMessage(Message):
    """Indicates that some errror has occurred"""
    def __init__(self,message):
        self.message = message
    
    def render(self):
        m = "error {} {}".format(len(self.message), self.message)
        return m.encode()

class LeaveMessage(Message):
    def __init__(self, channel):
        self.channel = channel

'''
class BlockMessage(Message):
    def __init__(self, blockeduser):
        self.blockeduser = blockeduser
'''

class ExchangeKey(Message):
    def __init__(self, fromuser, touser, key):
        self.fromuser = fromuser
        self.touser = touser
        self.key = key

    def render(self):
        m = "exchangekey {} {} {}".format(self.fromuser, self.touser, self.key)
        return m

class ProcessFile(Message):
    def __init__(self, destination, filepath, filesize):
        self.destination = destination
        self.filepath = filepath
        if filepath != None:
            self.filesize = filesize
        else:
            filepath = None


