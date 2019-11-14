'''
This is a key-policy ABE. 
We employ sha256 and xor operation to support any arbitrary random strings from [1, p], instead of group elements from GT.
'''

from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, GT, pair
from charm.toolbox.ABEnc import ABEnc
from msp import MSP
import hashlib

class ABE(ABEnc):
    def __init__(self, group_obj, assump_size, verbose=False, htype='sha256'):
        ABEnc.__init__(self)
        self.group = group_obj
        self.assump_size = assump_size  # size of linear assumption, at least 2
        self.util = MSP(self.group, verbose)
	self.hash_type = htype

    def setup(self):
        """
        Generates master public key and master secret key.
        """

        # generate two instances of the k-linear assumption
        A = []
        B = []
        for i in range(self.assump_size):
            A.append(self.group.random(ZR))
            B.append(self.group.random(ZR))  # note that A, B are vectors here

        # vector includes d_1, d_2, d_3
        k = []
        for i in range(self.assump_size + 1):
            k.append(self.group.random(ZR))

        # pick a random element from the two source groups and pair them
        g = self.group.random(G1)
        h = self.group.random(G2)
        e_gh = pair(g, h)


        # compute the [A]_2 term includes h^{a_1}, h^{a_2}, h
        h_A = []
        for i in range(self.assump_size):
            h_A.append(h ** A[i])
        h_A.append(h)

        # compute the e([k]_1, [A]_2) term, g_k includes g^{d_1}, g^{d_2}, g^{d_3}
        g_k = []
        for i in range(self.assump_size + 1):
            g_k.append(g ** k[i])

        e_gh_kA = []
        for i in range(self.assump_size):
            e_gh_kA.append(e_gh ** (k[i] * A[i] + k[self.assump_size]))

        # the public key
        mpk = {'h_A': h_A, 'e_gh_kA': e_gh_kA}

        # the master secret key
        msk = {'g': g, 'h': h, 'g_k': g_k, 'A': A, 'B': B}

        return mpk, msk

    def keygen(self, mpk, msk, policy_str):
        """
        Generate a key under a policy string.
        """

        policy = self.util.createPolicy(policy_str)
        mono_span_prog = self.util.convert_policy_to_msp(policy)
        num_cols = self.util.len_longest_row # max col = 3 in this example

        # pick randomness
        r = []
        sum = 0
        for i in range(self.assump_size):
            rand = self.group.random(ZR)
            r.append(rand)
            sum += rand

        # first compute Br, which includes b_1 * r_1, b_2 * r_2, r_1 + r_2
        Br = []
        for i in range(self.assump_size):
            Br.append(msk['B'][i] * r[i])
        Br.append(sum)

        # compute the [Br]_2 term, which includes h^{b_1 * r_1], h^{b_2 * r_2}, h^{r_1 + r_2}
        K_0 = []
        for i in range(self.assump_size + 1):
            K_0.append(msk['h'] ** Br[i])

	# compute keys
        K = {}
        A = msk['A']
        g = msk['g']
    	g_k = msk['g_k']
 	
	# len(sigma_col) = 2
        sigma_col = [] 
        for j in range(num_cols-1):
            rand = self.group.random(ZR)
    	    sigma_col.append(rand)
	
        # The we compute the [ attribute y in S ]_1 terms	
	for attr, row in mono_span_prog.items():
            k = []
	    sigma_attr = self.group.random(ZR)
            cols = len(row)
            attr_stripped = self.util.strip_index(attr)  # no need, re-use not allowed

	    #sk_i_1/2
	    for t in range(self.assump_size):
		a_t = A[t]
		prod1 = 1
		for j in range(1, cols): # j = [1, 2]
		    prodt1 = 1	
	
		    for l in range(self.assump_size + 1):
			input_for_hash_1 = '0' + str(j+1) + str(l) + str(t) # l = [0, 1, 2], t = [0, 1]		
			prodt2 = self.group.hash(input_for_hash_1, G1)
			prodt2 = prodt2 ** (Br[l] / a_t)
			prodt1 *= prodt2
		    # g^(sig_p_j/a_t)
		    prodt2 = g ** (sigma_col[j-1] / a_t )
		    prodt1 *= prodt2
		    prodt1 = prodt1 ** (row[j])		
		    #print(prodt1)    
		    prod1 *= prodt1
 
		for l in range(self.assump_size + 1):
		    input_for_hash_2 = attr_stripped + str(l) + str(t)  # l = [0, 1, 2], t = [0, 1]	
		    prodt1 = self.group.hash(input_for_hash_2, G1) ** (Br[l] / a_t)
		    prod1 *= prodt1

		prodt1 = g ** (sigma_attr/a_t)
		prod1 *= prodt1
		prodt1 = (g_k[t]) ** (row[0])
		prod1 *= prodt1
		k.append(prod1) # sk_i1, sk_i2

	    prod1 = 1	    
	    for j in range(1, cols):	# j = [1, 2]
		prod1 *= (g ** (-sigma_col[j-1]) ) ** (row[j])
	    prod1 *= g ** (-sigma_attr)
	    prod1 *= (g_k[self.assump_size]) ** (row[0]) #sk_i3
	    k.append(prod1)
            K[attr] = k

        return {'policy': policy, 'K_0': K_0, 'K': K}

    def encrypt(self, mpk, msg, attr_list):
        """
        Encrypt a message msg for a list of attributes.
        """

        # pick randomness
        s = []
        sum = 0
        for i in range(self.assump_size):
            rand = self.group.random(ZR)
            s.append(rand)
            sum += rand

        # compute the [As]_2 term, h^{a_1 * s_1}, h^{a_2 * s_2}, h^{s_1 * s_2}
        C_0 = []
        h_A = mpk['h_A'] 
        for i in range(self.assump_size):
            C_0.append(h_A[i] ** s[i]) 
        C_0.append(h_A[self.assump_size] ** sum) 

        # compute the [Ws]_1 terms

        C = {}
        for attr in attr_list:
            ct = []
            for l in range(self.assump_size + 1):
                prod = 1
                for t in range(self.assump_size):
                    input_for_hash = attr + str(l) + str(t) # l = [0,1,2], t= [0,1]
                    prod *= (self.group.hash(input_for_hash, G1) ** s[t])
                ct.append(prod)
            C[attr] = ct

        # compute the e(g, h)^(k^T As) . msg term
        Cp = 1
        for i in range(self.assump_size):
            Cp = Cp * (mpk['e_gh_kA'][i] ** s[i])	 
	
	sha256 = hashlib.new(self.hash_type)
	sha256.update(self.group.serialize(Cp))
	x = sha256.hexdigest() 
	Cp = msg^(int(x,16))

        return {'attr_list': attr_list, 'C_0': C_0, 'C': C, 'Cp': Cp}

    def decrypt(self, mpk, key, ctxt):
        """
        Decrypt ciphertext ctxt with decryption key.
        """

        nodes = self.util.prune(key['policy'], ctxt['attr_list'])
        if not nodes:
            # print ("Policy is not satisfied.")
            return None

        prod1_GT = 1
        prod2_GT = 1
        for i in range(self.assump_size + 1):
            prod_H = 1
            prod_G = 1
            for node in nodes:
                attr = node.getAttributeAndIndex()
                attr_stripped = self.util.strip_index(attr)  # no need, re-use not allowed
		prod_H *= key['K'][attr][i]
		prod_G *= ctxt['C'][attr_stripped][i]
	    prod1_GT *= pair(prod_H, ctxt['C_0'][i])
            prod2_GT *= pair(prod_G, key['K_0'][i])
	    #Cp = prod2_GT / prod1_GT
	    Cp = prod1_GT / prod2_GT

	sha256 = hashlib.new(self.hash_type)
	sha256.update(self.group.serialize(Cp))
	x = sha256.hexdigest()

        return ctxt['Cp']^(int(x,16))
