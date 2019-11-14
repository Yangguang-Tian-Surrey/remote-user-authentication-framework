'''
This is a fuzzy extractor with a Schnorr signature. 
We choose large prime numbers, including p, q, to form public paramaters for Schnorr groups. 
'''
from fuzzy_extractor import FuzzyExtractor
import string
import random
import math
import hashlib

from sympy import isprime

def toHex(s):
    output = []
    for ch in s:
	ch = ord(ch)
	int1 = ch/16
	output.append(getHex(int1))
	int2 = ch%16
	output.append(getHex(int2))
    return "".join(output)

def getHex(s):
    if s < 10:
	return chr(ord('0') + s)
    else:
        return chr(ord('A') + s-10)


class FE_DS():

	# The chosen parameters must satisfy p = q*r + 1, r =2
	def setup(self):

    	    self.p = 115792089237316195423570985008687907852837564279074904382605163141518161494337
    	    self.q = 341948486974166000522343609283189
    	    self.r = 338624364920977752681389262317185522840540224
    	    self.h = 3141592653589793238462643383279502884197
    
    	    assert(isprime(self.p))
    	    assert(isprime(self.q))
    	    assert(self.p-1 == self.q * self.r)
    
    	    self.g = pow(self.h, self.r, self.p)
    	    assert(self.g != 1)
    	    assert(pow(self.g, self.q, self.p) == 1)
	    return (self.p,self.q,self.g)
	    
	def fuzzy_extractor_gen(self,bio):

	    extractor = FuzzyExtractor(16, 2) # '16' means biometrics length, '2' is the hamming errors that can handle.
	    (key, helper) = extractor.generate(bio)
	    return (key, helper)

	def fuzzy_extractor_rep(self,fbio,helper):

	    extractor = FuzzyExtractor(16, 2) 
            r_key = extractor.reproduce(fbio, helper)  # r_key will probably still equal key!
	    return (r_key)

	def keygen(self,r_key):
            sha256 = hashlib.sha256()
	    sha256.update(str(toHex(r_key)).encode('ASCII'))
	    x = sha256.hexdigest()
            g_x = pow(self.g, int(x,16), self.p)
            return (x, g_x)

        def sig(self, m, x):
            r = random.randint(1, self.p)
            g_r = pow(self.g, r, self.p)
            sha256 = hashlib.sha256()
            sha256.update(str(m).encode('ASCII'))
            sha256.update(str(g_r).encode('ASCII'))
            e_0 = int(sha256.hexdigest(), 16) % self.q
            s_0 = (r - x * e_0) % self.q
            return (e_0, s_0)

        def verify(self, sigma , m, g_x):
            g_s = pow(self.g, sigma[1], self.p)
            g_e = pow(g_x, sigma[0], self.p)
            v_1 = g_s * g_e % self.p
            sha256 = hashlib.sha256()
            sha256.update(str(m).encode('ASCII'))
	    #sha256.update('ABC'.encode('ASCII')) #if sha256 is modifed by an attacker (e.g., m' = m + 'ABC'), then the verification fails
            sha256.update(str(v_1).encode('ASCII'))
            e_1 = int(sha256.hexdigest(), 16) % self.q    
            return sigma[0] == e_1

