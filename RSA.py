from random import randrange
from collections import namedtuple
from math import log, gcd
from binascii import hexlify, unhexlify
import hashlib

def is_prime(n, k=30):
    # Perform Rabin-Miller primality test
    # http://en.wikipedia.org/wiki/Miller%E2%80%93Rabin_primality_test
    if n <= 3:
        return n == 2 or n == 3
    neg_one = n - 1

    # write n-1 as 2^s*d where d is odd
    s, d = 0, neg_one
    while not d & 1:
        s, d = s+1, d>>1
    assert 2 ** s * d == neg_one and d & 1

    for i in range(k):
        a = randrange(2, neg_one)
        x = pow(a, d, n)
        if x in (1, neg_one):
            continue
        for r in range(1, s):
            x = x ** 2 % n
            if x == 1:
                return False
            if x == neg_one:
                break
        else:
            return False
    return True

def randprime(N=10**8):
    # Generate random prime
    p = 1
    while not is_prime(p):
        p = randrange(N)
    return p

def multinv(modulus, value):
    # Multiplicative inverse in a given modulus according to 
    # http://en.wikipedia.org/wiki/Extended_Euclidean_algorithm
    x, lastx = 0, 1
    a, b = modulus, value
    while b:
        a, q, b = b, a // b, a % b
        x, lastx = lastx - q * x, x
    result = (1 - lastx * modulus) // value
    if result < 0:
        result += modulus
    assert 0 <= result < modulus and value * result % modulus == 1
    return result

KeyPair = namedtuple('KeyPair', 'public private')
Key = namedtuple('Key', 'exponent modulus')

def keygen(N, public=None):
    # Generate public and private keys. N = key bit size
    prime1 = randprime(N)
    prime2 = randprime(N)
    composite = prime1 * prime2
    totient = (prime1 - 1) * (prime2 - 1)
    if public is None:
        while True:
            private = randrange(totient)
            if gcd(private, totient) == 1:
                break
        public = multinv(totient, private)
    else:
        private = multinv(totient, public)
    assert public * private % totient == gcd(public, totient) == gcd(private, totient) == 1
    assert pow(pow(1234567, public, composite), private, composite) == 1234567
    return KeyPair(Key(public, composite), Key(private, composite))

def encode(msg, pubkey, verbose=False):
    chunksize = int(log(pubkey.modulus, 256))
    outchunk = chunksize + 1
    outfmt = '%%0%dx' % (outchunk * 2,)
    bmsg = msg.encode()
    result = []
    for start in range(0, len(bmsg), chunksize):
        chunk = bmsg[start:start+chunksize]
        chunk += b'\x00' * (chunksize - len(chunk))
        plain = int(hexlify(chunk), 16)
        coded = pow(plain, *pubkey)
        bcoded = unhexlify((outfmt % coded).encode())
        if verbose: print('Encode:', chunksize, chunk, plain, coded, bcoded)
        result.append(bcoded)
    return b''.join(result)

def decode(bcipher, privkey, verbose=False):
    chunksize = int(log(pubkey.modulus, 256))
    outchunk = chunksize + 1
    outfmt = '%%0%dx' % (chunksize * 2,)
    result = []
    for start in range(0, len(bcipher), outchunk):
        bcoded = bcipher[start: start + outchunk]
        coded = int(hexlify(bcoded), 16)
        plain = pow(coded, *privkey)
        chunk = unhexlify((outfmt % plain).encode())
        if verbose: print('Decode:', chunksize, chunk, plain, coded, bcoded)
        result.append(chunk)
    return b''.join(result).rstrip(b'\x00').decode()


if __name__ == '__main__':

    pubkey, privkey = keygen(2**32)
    msg = input("\nEnter your message here: ")

    print('\n', '-' * 20, "Encoding Results", '-' * 20, '\n')
    encoded_msg = encode(msg, pubkey, 1)
    print('\n', '-' * 20, "Decoding Results", '-' * 20, '\n')
    decoded_msg = decode(encoded_msg, privkey, 1)
    print('-' * 20, '\n')

    print('\n', '-' * 20, "Final RSA Results", '-' * 20, '\n')
    print("Plain text: ", repr(msg))
    print("Encoded Message: ", encoded_msg)
    print("Decoded Message: ", repr(decoded_msg))
    print('\n')

    print("-" * 20 , "SHA3 Hash", "-" * 20)
    test_msg = str.encode(msg)
    obj_sha3_256 = hashlib.sha3_256(test_msg)
    print("\nExpected Hash (Hex digested): ", obj_sha3_256.hexdigest())

    test_decoded_msg = str.encode(decoded_msg)
    obj_sha3_256_decoded = hashlib.sha3_256(test_decoded_msg)
    print("\nGenerated Hash (Hex digested): ", obj_sha3_256_decoded.hexdigest(), '\n')

    if(obj_sha3_256_decoded.digest() == obj_sha3_256.digest()):
        print("Hashes match!\n")
    else:
        print("Hashes don't match!\n")



