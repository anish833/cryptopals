def challenge_three( xord ): #bruteforcing to find the key
	
	result = []
	for i in range(97,123):
		result = pwnlib.util.fiddling.xor(xored, chr(i))  #not fully automated but see the byte that make more sense
		print(result)
		
def with_key( xord ): #decrypting with the key
	
	result = pwnlib.util.fiddling.xor(xored, 120)
	return result

xored = unhexlify("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
get = with_key(xored)
print("\nChallenge 3 ---> " + get.replace(b'\x00', b' ').replace(b'\x07', b'\'').swapcase().decode("ascii")) #..converting back to ascii
