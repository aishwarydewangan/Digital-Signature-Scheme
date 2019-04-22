import math
import random as rand

ip = '127.0.0.1'
port = 17081


def modular_power(number, exponent, modular):
    res = 1
    number = number % modular

    while exponent > 0:
        if exponent % 2:
            res = (res * number) % modular

        exponent >>= 1
        number = (number ** 2) % modular

    return res

def miller_rabin(num, multiplier):
    # Step 2: Choosing a random_val in the range [2, n-2]

    num = max(num, 3)

    a_random = rand.randint(2, (num - 1))

    # Step 3: Computing Modular Exponentiation & Checking the primality Conditions
    b_0 = modular_power(a_random, multiplier, num)

    if b_0 == 1 or b_0 == num - 1:
        return True

    while multiplier < num - 1:

        b_0 = modular_power(b_0, 2, num)

        multiplier *= 2

        if b_0 == 1:
            return False
        if b_0 == num - 1:
            return True

    # If multiplier reached inputForPrime-1 => composite
    return False


def isPrime(num):

    # Step1: Computing k & m such that n-1 = 2^k * m (for some odd m)
    multiplier = num - 1

    while multiplier % 2 == 0:
        multiplier /= 2

    multiplier = int(multiplier)

    # Now repeat the test for RABIN_TEST_FREQUENCY time
    for _ in range(10):
        if not miller_rabin(num, multiplier):
            return False

    return True


def extended_gcd(x, y):
    x0, x1, y0, y1 = 1, 0, 0, 1

    while y != 0:
        q, x, y = x / y, y, x % y
        x0, x1 = x1, x0 - q * x1
        y0, y1 = y1, y0 - q * y1

    return x0

class Header:
    def __init__(self, opcode, cmd, source='127.0.0.1', destination='127.0.0.1'):
        self.opcode = opcode  
        self.cmd = cmd
        self.source = source  
        self.destination = destination  

class Signature:
    def __init__(self, c, s):
        self.c = c
        self.s = s

class Message:
    def __init__(self, header, p, g, y1, y2, buf, signature, status):
        self.header = header
        self.p = p   
        self.g = g   
        self.y1 =y1  
        self.y2 = y2 
        self.buf = buf 
        self.signature = signature 
        self.status = status 

