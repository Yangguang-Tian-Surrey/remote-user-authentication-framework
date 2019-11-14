'''
:Authors:         Yangguang Tian et al.
:Date:            11/2019
Comment: The protocol below has enrollment and authentication stages. Essentially, the protocol includes a fuzzy extractor scheme (Canetti, et al. "Reusable fuzzy extractors for low-entropy distributions." in EUROCRYPT 2016), a Schnorr signature scheme, and a KP-ABE scheme (Agrawal, Shashank, and Melissa Chase. "FAME: Fast Attribute-based Message Encryption." in ACM CCS 2017). The signature scheme can also be initiated as Waters scheme, because both Schnorr and Waters digital signature schemes has homomorphic property regarding to signing keys and signatures. 

1. This is running at Python 2.7.15+, [GCC 7.4.0] on linux2. In order to run the protocol, you must install fuzzy-extractor and charm framework, respectively (from github). 
2. 10 biometrics are involved in the fuzzy extractor. The success of underlying fuzzy extractor is NOT 100% here, it tolerates small chance of false acceptance and rejection. 
3. The client's public key acts as an attribute, which will be used to generate a ciphertext of ABE. The attribute must be in the format of either '123' or 'abc' (the format of 'a1b2c3' is not allowed due to the MSP in ABE scheme). 
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
    bio_case = ['AAAAEEEEIIIINNNN','BBBBFFFFJJJJPPPP','CCCCGGGGLLLLQQQQ',
                'DDDDHHAHMMMMWWWW','AAAAEEAEIIIINNNN','BABBFFFFJJJJPPPP',
                'CCCCGGGGLLLLQQQA','DDDDHHHHMMMMWWWA','AAAAEEEAIIIINNNN',
                'BBBBFFFFJJJJPPAP']

    print "Client generates CRS from 1 to 10 att in ms:"
    for bio_len in range(0, len(bio_case)+1):
        bio = bio_case[0:bio_len]
        t1 = time.time()
        for times in range(0,100):
            fuzzy_pair = []
            key_pair = []
            for i in range(bio_len):
                fuzzy_pair.append(fs.fuzzy_extractor_gen(bio[i]))
                key_pair.append(fs.keygen(fuzzy_pair[i][0]))
        t2 = time.time()
        print (t2-t1)*10

    # Server generates a decryption key for an enrolled client under a policy. The policy is linked to the enrolled public keys (i.e., attributes), in the format of '12345'. 


    print "Server generates decryption keys from 1 to 10 policies in ms:"
    policy_str = []
    for i in range(10):
	sha256 = hashlib.sha256()
        sha256.update(str(key_pair[i][1]).encode('ASCII'))
        policy_str.append(str(int(sha256.hexdigest(), 16))[0:5])

    for ilen in range(1, len(policy_str)+1):
        t1 = time.time()
        policy_stri = "AND".join(policy_str[0:ilen])
        for i in range(10):
            for times in range(0,100):
                key = abe.keygen(mpk, msk, policy_stri)
        t2 = time.time()
        print (t2-t1)*10

    # This is Authentication.
    # Upon receiving an authentication request (user's ID) from a client, the server generates a challenge nonce n_0 and sends it back to user, along with enrolled helper strings.
    print "Authentication from 1 to 10 att in ms:"
    for j in range(1,10):
        t1 = time.time()
        for times in range(0,100):
            n_0 = random.randint(1, p) 

    # Client genearates a set of signing/verification keys using the derived fuzzy secret keys. 
            fuzzy_key = []
            keys = []
            fbio = ['AAAAEEEEIIIINNNN','BBBBFFFFJJJJPPPP','CCCCGGGGLLLLQQQQ',
            'DDDDHHAHMMMMWWWW','AAAAEEAEIIIINNNN','BABBFFFFJJJJPPPP',
            'CCCCGGGGLLLLQQQA','DDDDHHHHMMMMWWWA','AAAAEEEAIIIINNNN',
            'BBBBFFFFJJJJPPAP']


            for i in range(j):
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
        t2 = time.time()
        print (t2-t1)*10

if __name__ == "__main__":
    main()
