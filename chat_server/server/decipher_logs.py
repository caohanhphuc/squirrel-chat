import glob
import sys
import string
import base64
import cryptography
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def extract_key(key_file):
	with open(key_file, "r") as file:
		key = file.read()
		string.strip(key)
	return key

def decrypt_logs(channel, password):
	#key = extract_key(key_file)
	if channel.startswith('#'):
		channel = channel[1:]
	logfile_list = glob.glob("logs/log-" + channel + "*.log")
	if len(logfile_list) == 0:
		print("No log found for channel " + channel)
		return
	logfile_list.sort()
	for logfile in logfile_list:
		with open(logfile, 'rb') as file:
			print(logfile)
			salt = str.strip(file.readline())
			msg_encrypted = file.readline()
			try:
				kdf = PBKDF2HMAC(
		                        algorithm=hashes.SHA256(),
		                        length=32,
		                        salt=salt,
		                        iterations=100000,
		                        backend=default_backend()
		                        )
				key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
				fernet = Fernet(key)
				msg_decrypted = fernet.decrypt(msg_encrypted)
				signature = str.strip(file.readline())
			 	h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
			 	try:
			 		h.update(msg_decrypted)
			 		h.verify((signature))
			 		print("Message authenticity confirmed! Message log is as follows: ")
			 		print(msg_decrypted)
			 	except cryptography.exceptions.InvalidSignature:
			 		print("Invalid signature!")
			except cryptography.fernet.InvalidToken:
		 		print("Not permitted to read channel logs in " + logfile)
		file.close()
	return

if len(sys.argv) < 3:
	print("Please follow the format: python decipher_logs.py <channel_name> <key>")
	sys.exit(0)

decrypt_logs(sys.argv[1], sys.argv[2])