'''
The authentication policy has four attributes
'''

from charm.toolbox.pairinggroup import PairingGroup, GT
from KP_ABE import ABE
from test_with_DS import FE_DS
import random
import hashlib
import time

def main():
    
    # This is Enrollment.
    # Server instantiates a bilinear pairing map, runs the setup of KP-ABE, and runs the setup of FE_DS. 
    pairing_group = PairingGroup('MNT224')
    abe = ABE(pairing_group, 2) 
    (mpk, msk) = abe.setup()

    fs = FE_DS()
    (p,q,g) = fs.setup()
    
    # Client generates an attribute set: {public key, helper string} by running the generation of fuzzy extractor.
    
    fuzzy_pair = []
    key_pair = []
    bio = ['AAAAEEEEIIIINNNN','BBBBFFFFJJJJPPPP','CCCCGGGGLLLLQQQQ','DDDDHHHHMMMMWWWW']
    for i in range (len(bio)):
        fuzzy_pair.append(fs.fuzzy_extractor_gen(bio[i]))
        key_pair.append(fs.keygen(fuzzy_pair[i][0]))

    # Server generates a decryption key for an enrolled client under a policy. The policy is linked to the enrolled public keys (i.e., attributes), in the format of '12345'. 

    policy_str = []
    for i in range(4):
	sha256 = hashlib.sha256()
        sha256.update(str(key_pair[i][1]).encode('ASCII'))
        policy_str.append(str(int(sha256.hexdigest(), 16))[0:5])

    policy_str = '(%s AND %s) AND (%s AND %s)' % (policy_str[0], policy_str[1], policy_str[2], policy_str[3])  # the policy can be changed. 
    key = abe.keygen(mpk, msk, policy_str)

    # This is Authentication.
    # Upon receiving an authentication request (user's ID) from a client, the server generates a challenge nonce n_0 and sends it back to user, along with enrolled helper strings.
    n_0 = random.randint(1, p) 

    # Client genearates a set of signing/verification keys using the derived fuzzy secret keys. 
    fuzzy_key = []
    keys = []
    fbio = ['AAAAEEEEIIIINNZZ','BBBBFFFFJJJJPPZZ','CCCCGGGGLLLLQQZZ','DDDDHHHHMMMMWWZZ']
    for i in range(len(fbio)):
	fuzzy_key.append(fs.fuzzy_extractor_rep(fbio[i],fuzzy_pair[i][1]))	
	if fuzzy_pair[i][0] == fuzzy_key[i]:
	   keys.append(fs.keygen(fuzzy_key[i]))

    # Client chooses a response nonce n_1, and generates a ciphertext according to the derived verification keys.

    n_1 = random.randint(1, p)

    attr_list = [] 
    for i in range(len(keys)):
	sha256 = hashlib.sha256()
        sha256.update(str(keys[i][1]).encode('ASCII'))
        attr_list.append(str(int(sha256.hexdigest(), 16))[0:5])

    ctxt = abe.encrypt(mpk, n_1, attr_list)

    # Client genearates a digital signature on msg = (n_0, n_1) using an 'aggregrated' secret key sk. 
    msg1 = [] 
    msg1.append(n_0)
    msg1.append(n_1)

    sk = 0
    pk = 1
    for i in range(len(keys)):       
	sk = (sk + int(keys[i][0], 16)) % q
	pk = (pk * keys[i][1]) % p
    sigma = fs.sig(msg1, sk)

    # Server obtains n_1 by decryption, and verifies the message-signature pair (msg, sigma) using the 'aggregrated' public key pk.

    msg2 = [] 
    msg2.append(n_0)
    msg2.append(abe.decrypt(mpk, key, ctxt))
    v = fs.verify(sigma, msg2, pk)
    if not v:
        print(policy_str, attr_list)
    # print('Verification of message-signature:', v)
    return v

if __name__ == "__main__":
   counter = 0
   for i in range(0,100):
       counter += main()
   print('Verification of message-signature:', counter)
   
