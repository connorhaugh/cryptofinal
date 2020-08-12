from Crypto.Util import number
from Crypto.Random import random
from primegen import generate_prime_number

class SessionKeyGenerator:

    #TODO: GENERATE LARGER PRIMES

    #Produces DH1 = [g1X1mod(p1), g2x2mod(p2) , g1,g2,p1,p2]). See Design Document for details on each element
    def generate_dh1():
        #generate two large primes. to do so, generate a list of large primes and choose two randomly.
        P1 = generate_prime_number() # Strong primes have p-1 p+1 with a large prime factor.
        P2 = generate_prime_number()
        # create our generator G. from taking group theory that for all cyclic groups of prime numbers of order >2 all elements are generators so we can select one at random.
        G1 = random.randint(1, P1)
        G2 = random.randint(1, P2)

        # generate a random X1, X2.
        X1 = random.randint(1,P1)
        X2 = random.randint(1,P2)

        #do the math
        M1 = pow(G1,X1,P1)
        M2 = pow(G2,X2,P2)

        return {'M1':M1,'M2': M2, 'G1': G1,'G2': G2, 'P1': P1, 'P2': P2, 'X1': X1, 'X2': X2}

        #[MA,MB,Y1,Y2]
    def generate_dh2(G1,G2,P1,P2):
        Y1 = random.randint(1,2**4)
        Y2 = random.randint(1,2**4)
        MA=pow(G1,Y1,P1)
        MB=pow(G2,Y2,P2)
        return {'MA':MA,'MB':MB,'Y1':Y1,'Y2':Y2}

    def calculate_keys(M1,M2,X1,X2,P1,P2):
        KMESSAGE = pow(M1,X1,P1)
        KMAC = pow(M2,X2,P2)
        return [KMESSAGE.to_bytes(length=16, byteorder='big'),KMAC.to_bytes(length=16, byteorder='big')]

    def genNonce():
        return random.getrandbits(32)
