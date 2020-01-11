# remote-user-authentication-framework

We use Python to simulate a client-server user authentication from multiple (e.g., 4 and 8) biometircs at the local desktop. 

To simulate it, we need an attribute based encryption ABE (FAME: Fast Attribute-based Message Encryption, CCS17), and a fuzzy extractor FE (Reusable fuzzy extractors for low-entropy distributions, EUROCRYPT16). We assume the readers are familar with these two concepts. 

On a high level, we implement a key-policy attribute-based encryption KP-ABE scheme (KP_ABE.py, along with MAIN_attr4.py and MAIN_attr8.py, respectively) in Python using the Charm framework. Meanwhile, we implement a FE based Schnorr signature scheme (test_with_DS.py) in Python. 

The main file (Main.py) includes enrollment and authentication. The detailed description of the underlying building blocks can be found in Main.py. Spefically, the enrollment stage includes: 1) the server instantiates a bilinear pairing map, runs the setup of KP-ABE, and runs the setup of FE_DS; 2) the client generates an attribute set: {public key, helper string} by running the generation of fuzzy extractor; 3) The server generates a decryption key for an enrolled client under a policy. The policy is linked to the enrolled public keys (i.e., attributes).

The user authentication mainly includes a challenge-response process (with randomly-chosen nonces), an encryption and decryption in ABE, a reproceduce algorithm in FE, and a message-signature generation and verification. 
