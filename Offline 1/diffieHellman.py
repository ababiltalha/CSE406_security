import random
import time

# a ^ b mod c
def modulo(a, b, c):
    x = 1
    y = a
    while b > 0:
        if b % 2 == 1:
            x = (x * y) % c
        y = (y * y) % c
        b //= 2
    return x % c

# a * b mod c
def mulmod(a, b, c):
    x = 0
    y = a % c
    while b > 0:
        if b % 2 == 1:
            x = (x + y) % c
        y = (y * y) % c
        b //= 2
    return x % c

# Miller-Rabin primality test (10 iterations)
# True if p is prime, False if p is composite
def MillerRabin(p, iteration = 10):
    if p < 2:
        return False
    if p != 2 and p % 2 == 0:
        return False
    
    s = p - 1
    while s % 2 == 0:
        s //= 2
    
    for i in range(iteration):
        a = random.randint(1, p - 1)
        temp = s
        mod = modulo(a, temp, p)
        
        while temp != p - 1 and mod != 1 and mod != p - 1:
            mod = mulmod(mod, mod, p)
            temp *= 2
        
        if mod != p - 1 and temp % 2 == 0:
            return False
    
    return True

# Generate a k-bit prime
# safe prime: p = 2*q + 1, where q is also prime
def genPrime(k):
    while True:
        q = random.randint(2**(k-2), 2**(k-1) - 1) 
        if MillerRabin(q):
            if MillerRabin(2*q + 1):
                return 2*q + 1
        
# Generate primitive root modulo p, g
def genPrimitiveRoot(p, candidateMin = 2, candidateMax = (10**10 - 1)): 
    if p == 2: 
        return 1
    p1 = 2
    p2 = (p - 1) / p1
    
    while True:
        g = random.randint(candidateMin, candidateMax)
        if not (modulo(g, (p - 1) / p1, p) == 1) and not modulo(g, (p - 1) / p2, p) == 1: 
            return g
     
# Generate secret private keys a and b
# primes of k/2 bits
def genSecretPrivateKeys(k):
    a = genPrime(k/2)
    b = genPrime(k/2)
    while b == a:
        b = genPrime(k/2)
    return a, b

# Generate public keys A and B
def genPublicKeys(p, g, a, b):
    A = modulo(g, a, p)
    B = modulo(g, b, p)
    return A, B

# Generate shared secret key s
def genSharedSecretKey(p, A, b):
    return modulo(A, b, p)

def testDiffieHellman(k):
    pTime ,gTime, abTime, ABTime, sTime = 0, 0, 0, 0, 0
    for i in range(5):
        # generate large prime p
        startTime = time.time()
        p = genPrime(k)
        pTime += time.time() - startTime
        # print("p =", p)
        
        # generate primitive root g
        startTime = time.time()
        g = genPrimitiveRoot(p)
        gTime += time.time() - startTime
        # print("g =", g)
        
        # generate secret private keys a and b
        startTime = time.time()
        a, b = genSecretPrivateKeys(k)
        abTime += (time.time() - startTime)
        # print("a = " + str(a) + ", b = " + str(b))
        
        # generate public keys A and B
        startTime = time.time()
        A, B = genPublicKeys(p, g, a, b)
        ABTime += (time.time() - startTime)
        # print("A = " + str(A) + ", B = " + str(B))
        
        # generate shared secret key
        startTime = time.time()
        aliceSharedSecretKey = genSharedSecretKey(p, B, a)
        sTime += time.time() - startTime
        bobSharedSecretKey = genSharedSecretKey(p, A, b)
        
        # verify shared secret key
        if aliceSharedSecretKey != bobSharedSecretKey:
            print("Error: Shared secret keys do not match")
            break
    # return average time over 5 trials in milliseconds
    return round(pTime*1000/5, 6), round(gTime*1000/5, 6), round(abTime*1000/10, 6), round(ABTime*1000/10, 6), round(sTime*1000/5, 6)
    
        
def main():
    k = [128, 192, 256]
    print("Time to compute for k = 128, 192, 256\n")
    print("k\t\t\tp (ms)\t\t\tg (ms)\t\t\ta,b (ms)\t\tA,B (ms)\t\ts (ms)")
    for i in k:
        pTime ,gTime, abTime, ABTime, sTime = testDiffieHellman(i)
        print(str(i) + "\t\t\t" + str(pTime) + "\t\t" + str(gTime) + "\t\t" + str(abTime) + "\t\t" + str(ABTime) + "\t\t" + str(sTime))
    return
    
if __name__ == "__main__":
    main()