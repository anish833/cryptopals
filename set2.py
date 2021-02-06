#!/usr/bin/env python3

from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import AES
import base64
import codecs
import random
from Crypto.Random import get_random_bytes
from paddown import Paddown


#Challenge 9 -- Implement PKCS#7 padding

def challenge_nine( data ):
	return pad(data, 20)  	#Used pycryptodome library to add the pad of 20 bytes

print("Challenge 9 --->")
print(challenge_nine(b'YELLOW SUBMARINE')) #Returned in bytes

#Challenge 10 -- Implement CBC mode

def challenge_ten():
	
	key = 'YELLOW SUBMARINE'
	iv = bytes(chr(0) * AES.block_size, encoding = 'utf-8')  # getting the initialization vector 
	cbc = AES.new(key.encode('utf-8'), AES.MODE_CBC, iv)
	with codecs.open('/home/kali/Downloads/cbc.txt', encoding="utf8", errors='ignore') as f:
		data = unpad(cbc.decrypt(base64.b64decode(f.read())), AES.block_size) #decrypting cbc and decoding base64 while reading
	print("\nChallenge 10 --->\n" + data.decode('utf-8'))

challenge_ten()

#Challenge 11 -- An ECB/CBC detection oracle

def challenge_eleven( message ):

	r1 = random.randint(0,1)
	if r1 == 0:
		cipher = ecb(message)
	else:
		cipher = cbc(message)
	return cipher

def ecb( message ):
	
	key = get_random_bytes(16)
	aes = AES.new(key, AES.MODE_ECB)
	ct_bytes = aes.encrypt(pad(message, AES.block_size))
	ct = base64.b64encode(ct_bytes).decode('utf-8')
	return ct

def cbc( message ):

	key = get_random_bytes(16)
	aes = AES.new(key, AES.MODE_CBC)
	ct_bytes = aes.encrypt(pad(message, AES.block_size))
	iv = base64.b64encode(aes.iv).decode('utf-8')
	ct = base64.b64encode(ct_bytes).decode('utf-8')
	return ct

class InvalidPadding(BaseException):
    pass
class MyPaddown(Paddown):
	def has_valid_padding(self, ciphertext):
		try:
			
			return True
		except InvalidPadding:
			return False
		return False

#cipher = challenge_eleven(pad(b'YELLOW SUBMARINE', 16))
#dec =  MyPaddown(base64.b64decode(cipher.encode())).decrypt()
#print(dec)

#Challenge 15 -- PKCS#7 padding validation

def challenge_fifteen( message ):

	try:
		return unpad(message,16)  #Check if the padding is correct
	except ValueError:
		print("Invalid Padding")
	
	return " "

message = b"ICE ICE BABY\x04\x04\x04\x04"
print("Challenge 15 --->\n" + challenge_fifteen(message).decode('utf-8'))


#left with challenge 11,12,13,14 and 16
