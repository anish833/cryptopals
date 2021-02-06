#!/usr/bin/env python3

from binascii import unhexlify, b2a_base64
from pwn import *
import base64
from Crypto.Cipher import AES
import re
import enchant


#Cryptopals Set 1 - Basics

#Challenge 1 -- hex to base64

def challenge_one( newhex ):
	
	result = b2a_base64(unhexlify(newhex))  #unhexlify for converting hex to bytes and b2a_bas64 is to convert to base64
	return result

hextext = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
print("Challenge 1 ---> " + challenge_one(hextext).decode("utf-8")) # decode("utf-8") for removing byte strings b'text'

#Challenge 2 -- Fixed XOR

def challenge_two( hex1,hex2 ):
	
	result = "".join(chr(x ^ y) for x, y in zip( hex1, hex2)) # xoring each character using zip function which terminates after parsing all the characters
	return result

first_hex = unhexlify("1c0111001f010100061a024b53535009181c")
sec_hex = unhexlify("686974207468652062756c6c277320657965")

print("Challenge 2 ---> " + challenge_two( first_hex, sec_hex).encode("utf-8").hex()) # decoding back to hex 

#Challenge 3 -- Single-byte XOR cipher

edict = enchant.Dict("en_US")
def challenge_three(bstr):
	sols = []
	mostlikelysol = {"true": 0, "sol": ""}
	for i in range(255):
		sol = pwnlib.util.fiddling.xor(bstr, i)
		sols.append(sol)
		if 32 in list(sol):
			# print(sol)
			# print(sol.decode("ascii"))
			solwords = sol.decode("ascii").split(" ")
			try:
				totaltrue = 0
				soldictcheck = list(map(edict.check, solwords))
				totaltrue = 0 + soldictcheck.count(True)
				# if True in soldictcheck:
				#     print(solwords, soldictcheck, totaltrue, mostlikelysol["sol"])
				if totaltrue > mostlikelysol["true"]:
					mostlikelysol["sol"] = sol.decode("utf-8")
					mostlikelysol["true"] = totaltrue
			except:
				pass
	# print(mostlikelysol)
	# return sols
	return mostlikelysol


bstr = bytes.fromhex("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
# * for array unpacking
# print(*challenge_three(bstr), sep="\n")
print("\nChallenge 3 --->")
print(challenge_three(bstr))


#Challenge 4 -- Detect single-character XOR

def challenge_four(bstrings: list):
	valid_bstrings = []
	for bstr in bstrings:
		try:
			bstr.decode("ascii")
			valid_bstrings.append(challenge_three(bstr))
		except UnicodeDecodeError:
			pass
	return valid_bstrings


c4_bstrings = [bytes.fromhex(line.strip()) for line in open("/home/kali/Downloads/xor.txt").readlines()]
# print(*c4_bstrings, sep="\n")
print("\nChallenge 4 --->")
print(*challenge_four(c4_bstrings), sep="\n")
# [print(bstri) for bstri in challenge_four(c4_bstrings)]

#Challenge 5 -- Implement repeating-key XOR

def challenge_five( text ):
	i = 0
	key = "ICE"
	result = []
	for ch in text:
		result += pwnlib.util.fiddling.xor(ch, key[i]) #Xored each word with each alphabet of key
		i = i + 1
		if i == 3:                              #repeat when reached the last character of the key
			i = 0

	return result
	

text = "Burning 'em, if you ain't quick and nimble I go crazy when I hear a cymbal"
print("\nChallenge 5 ---> " + bytes(challenge_five(text)).hex())

#Challenge 6 -- Break repeating-key XOR

def challenge_six():
	pass


#Challenge 7 -- AES in ECB mode

def challenge_seven():
	
	key = 'YELLOW SUBMARINE'
	aes = AES.new(key.encode(), AES.MODE_ECB)
	with open('/home/kali/Downloads/aes.txt', 'r') as f:
		data = aes.decrypt(base64.b64decode(f.read())).decode('utf-8')[:-4]  #decoding base64 , decoding aes-ecb, converting back to ascii while reading every character of the text file
	print("\nChallenge 7 --->\n" + data)   # data[:-4] removes the last 4 non-printable characters

challenge_seven()

#Challenge 8 -- Detect AES in ECB mode
'''
def challenge_eight():
	with open('/home/kali/Downloads/ecb.txt', 'r') as f:
		data = f.read()
	n = 16
	i = 0
	chunks = [data[i:i+n] for i in range(0, len(data), n)]
	while len(chunks):
		r = re.compile(chunks[i])
		i += 1
		newlist = len(re.findall(, chunks))
		print(newlist)

#challenge_eight() Not Completed

'''

#Left with - Challenge 6 and 8 in set 1



