# remote-user-authentication-framework

We use Python to simulate a client-server user authentication from multiple (e.g., 4 and 8) biometircs at the local desktop. The reason we use multiple biometrics is to deal with low-entropy issue. For example, user's biometrics may be compromised or damaged (due to aging).  

To simulate it, we need an attribute based encryption ABE (FAME: Fast Attribute-based Message Encryption, CCS17), a fuzzy extractor FE (Reusable fuzzy extractors for low-entropy distributions, EUROCRYPT16), and a digital signature scheme (e.g., Schnorr). We assume the readers are familar with these primitives. 

On a high level, we implement a key-policy attribute-based encryption KP-ABE scheme (KP_ABE.py, along with MAIN_attr4.py and MAIN_attr8.py, respectively) in Python using the Charm framework. We also implement a FE based Schnorr signature scheme (test_with_DS.py) in Python. 

The main file (Main.py) includes enrollment and authentication. The detailed description of the underlying building blocks can be found in Main.py. Spefically, the enrollment stage includes: 1) the server runs the setup of KP-ABE, and runs the setup of FE_DS; 2) the client generates an attribute set: {public key, helper string} by running the generation of fuzzy extractor; 3) The server generates a decryption key for an enrolled user under a policy. The policy is linked to the enrolled public keys (i.e., attributes).

The user authentication mainly includes a challenge-response process (including randomly-chosen nonces), an encryption and decryption of ABE, a reproceduce algorithm of FE, and a message-signature generation and verification. In particular, the user derives a set of secret/public key pairs using her nearby biometrics and the enrolled helper strings (or sketches). The server accepts the user if and only if: 1) the derived public keys satisfy the decryption key (so that decryption works); and 2) the message-signature is verified as valid under the derived public keys. 
