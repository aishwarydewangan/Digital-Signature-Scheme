import socket
import pickle
import utils
import hashlib
import pickle
import threading

soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
conn = None
addr = None

def verify_signature(msg, public_key, p, c, s):

	print '[+] Verifying Signature'
	g = public_key[0]
	y1 = public_key[1]
	y2 = public_key[2]

	y1_inv = utils.extended_gcd(y1, p)
	y2_inv = utils.extended_gcd(y2, p)

	A = (utils.modular_power(g, s, p) * utils.modular_power(y1_inv, c, p))%p
	B = (utils.modular_power(y1, s, p) * utils.modular_power(y2_inv, c, p))%p

	buf = str(A) + str(B) + str(msg)
	buf_sha = hashlib.sha1(buf).hexdigest()

	c_new = int(buf_sha, 16)

	if c != c_new:
		return False
	return True

def serve(conn):
	data = conn.recv(1024)

	if not data:
		print '[-] Data receive error'
		print '[-] Exiting'
		sys.exit()

	req = pickle.loads(data)

	if req.header.opcode == 10 and req.header.cmd == 'PUBKEY':
		p = req.p
		g = req.g
		y1 = req.y1
		y2 = req.y2
		public_key = (g, y1, y2)
		print '[+] Public Key Published'

		print '[+] Waiting for Signed Message by Client'
		data = conn.recv(1024)

		if not data:
			print '[-] Data receive error'
			print '[-] Exiting'
			sys.exit()

		req = pickle.loads(data)
		
		if req.header.opcode == 20 and req.header.cmd == 'SIGNEDMSG':
			print '[+] Signed Message received'
			signature = req.signature
			c = signature.c
			s = signature.s
			msg = req.buf

			if verify_signature(msg, public_key, p, c, s):
				print '[+] Digital Signature verified successfuly'
				header = utils.Header(30, 'VERSTATUS')
				message = utils.Message(header, None, None, None, None, None, None, 'GOOD')
				data = pickle.dumps(message)
				conn.send(data)
			else:
				print '[+] Digital Signature verification failed'
				header = utils.Header(30, 'VERSTATUS')
				message = utils.Message(header, None, None, None, None, None, None, 'BAD')
				data = pickle.dumps(message)
				conn.send(data)
		else:
			print '[-] Invalid opcode or command'
	else:
		print '[-] Invalid opcode or command'


if __name__ == '__main__':
	print '[+] Starting Server'
	soc.bind((utils.ip, utils.port))
	soc.listen(100)
	while True:
		conn, addr = soc.accept()
		t1 = threading.Thread(target=serve, args=(conn,))
		t1.start()