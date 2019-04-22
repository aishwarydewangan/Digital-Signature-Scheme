import sys, socket
import random, math
import hashlib
import utils 
import pickle
import time

def generate_key():

	# Find prime number P using Miller-Rabin Method
	p = random.randint(10000, 100000)

	while not utils.isPrime(p):
		p = random.randint(10000, 100000)

	# Find prime divisor
	q = 0

	for num in reversed(range(int(math.sqrt(p-1)))):
		if ((p-1)%num) == 0:
			if utils.isPrime(num):
				q = num
				break

    # Find primitive root
	g = 1
	while g == 1:
		h = random.randint(2, p)
		g = utils.modular_power(h, (p - 1) / q, p)

	# Secret Key
	private_key = random.randint(1, p-1)

	# Public Key Parameters
	y1 = utils.modular_power(g, private_key, p)

	y2 = utils.modular_power(y1, private_key, p)

	public_key = (g, y1, y2)

	return private_key, public_key, p

def generate_signature(msg, private_key, public_key, p):

	r = random.randint(1, p-1)
	g = public_key[0]
	y1 = public_key[1]
	y2 = public_key[2]

	A = utils.modular_power(g, r, p)
	B = utils.modular_power(y1, r, p)

	buf = str(A) + str(B) + str(msg)
	buf_sha = hashlib.sha1(buf).hexdigest()

	c = int(buf_sha, 16)
	s = (private_key*c) + r%p

	return c, s

if __name__ == '__main__':
	soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	print '[+] Starting Client'
	soc.connect((utils.ip, utils.port))
	print '[+] Connected to Server'

	print '[+] Generating Public Key'
	private_key, public_key, p = generate_key()

	print '[+] Publishing Public Key'
	g = public_key[0]
	y1 = public_key[1]
	y2 = public_key[2]
	header = utils.Header(10, 'PUBKEY')
	message = utils.Message(header, p, g, y1, y2, None, None, None)
	data = pickle.dumps(message)
	soc.send(data)
	print '[+] Public Key sent to Server'

	msg = raw_input('Enter message: ')
	print '[+] Generating Signature'
	c, s = generate_signature(msg, private_key, public_key, p)
	print '[+] Signature generated'

	header = utils.Header(20, 'SIGNEDMSG')
	signature = utils.Signature(c, s)
	message = utils.Message(header, p, g, y1, y2, msg, signature, None)
	data = pickle.dumps(message)
	print '[+] Sending signed message to server'
	soc.send(data)
	print '[+] Signed message sent to server'

	print '[+] Waiting for server for status'
	data = soc.recv(1024)
	print '[+] Status received'

	if not data:
		print '[-] Data receive error'
		print '[-] Exiting'
		sys.exit()

	resp = pickle.loads(data)

	if resp.header.opcode == 30 and resp.header.cmd == 'VERSTATUS':
		if resp.status == 'GOOD':
			print '[+] Digital Signature Verification Successful'
		else:
			print '[-] Digital Signature Verification Failed'
	else:
		print '[-] Invalid opcode or command'






