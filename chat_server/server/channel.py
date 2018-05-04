class Channel:
	#Represent a channel
	def __init__(self, channel_name, topic, members, admin, banlist):
		self.channel_name = channel_name
		self.topic = topic
		self.members = members
		self.admin = [admin]
		self.banlist = banlist
		self.current_log = ""
		self.msg_count = 0
		self.upload_dict = dict()