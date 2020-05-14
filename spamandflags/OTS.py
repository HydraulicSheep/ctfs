import secrets
import hashlib
import hmac
from pwn import *
import random
from itertools import product


#Connection to the server and receiving of key details
"""
sh=connect('34.89.64.81',1337)
x = sh.recvline_contains(b'pub_key = ')
x = sh.recvline_contains(b'pub_key = ')
x = sh.recvline_contains(b'pub_key = ')
public = x.split()[2]
x = str(sh.recvline())
message = x.split('"')[1]
signature = x.split()[6][0:-3]
"""

class OTS:
    def __init__(self):
        self.key_len = 128
        self.priv_key = secrets.token_bytes(16*self.key_len)
        self.pub_key = b''.join([self.hash_iter(self.priv_key[16*i:16*(i+1)], 255) for i in range(self.key_len)]).hex()

    def hash_iter(self, msg, n):
        assert len(msg) == 16
        for i in range(n):
            msg = hashlib.md5(msg).digest()
        return msg

    def wrap(self, msg):
        raw = msg.encode('utf-8')
        assert len(raw) <= self.key_len - 16
        raw = raw + b'\x00'*(self.key_len - 16 - len(raw))
        raw = raw + hashlib.md5(raw).digest()
        return raw

    def sign(self, msg):
        
        raw = self.wrap(msg)
        signature = b''.join([self.hash_iter(self.priv_key[16*i:16*(i+1)], 255-raw[i]) for i in range(len(raw))]).hex()
        self.verify(msg, signature)
        return signature

    def verify(self, msg, signature):
        raw = self.wrap(msg)
        signature = bytes.fromhex(signature)
        assert len(signature) == self.key_len * 16
        calc_pub_key = b''.join([self.hash_iter(signature[16*i:16*(i+1)], raw[i]) for i in range(len(raw))]).hex()
        assert hmac.compare_digest(self.pub_key, calc_pub_key)

    def test(self, string):
        raw = string.encode('utf-8')
        for char in raw:
            print(255-char)

    #Test if the payload checksum is greater than the signed message's checksum
    def checker(self,msg):
        checksum = self.wrap(msg)[-16:]
        string = 'My faflagR' 
        h = self.wrap(string)[-16:]
        print(h)
        good = True


        for x in range(16):
            if 255-h[x] < 255-checksum[x]:
                print(x)
                good = False
                break
        
        if good:
            print('GOOD')
            print(checksum.hex())
            print(self.wrap(string)[-16:].hex())
            return string
        else:
            print('ERROR')

    """
    #Search for low md5 checksums.
    def bruteforcer(self):
        t = ' !"#$%&\'()*abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ' #Only a subset of ASCII characters are really necessary, given the number of combinations.
        best=0
        checksum=""
        for n in range(128):
            for combo in product(t,repeat=n):
                string = "My faflag"+''.join(combo)
                h = self.wrap(string)[-16:]
                if checksum=="":
                    checksum=h

                good = True
                p = self.wrap(string)
                a = self.wrap("My favorite number is ")
                for i in range(min(len(a),len(string))):
                    if 255-p[i]< 255-a[i]:
                        good = False
                        break

                if not good:
                    continue
                a = 0
                for x in range(16):
                    a += math.exp((255-h[x]-128)/128)/(math.exp((255-h[x]-128)/128)+1)
                if a>best:
                    best = a
                    checksum = h
                    print('HIT')
                    print(string)
                    print(checksum.hex())
    """

    def payload(self,signature,public,message):
        #Checks if all bytes of the payload's checksum are lower than those of the signed message. Returns None if not matching. This throws an error later.
        newmessage = self.checker(message)
        signature = bytes.fromhex(signature)
        first = signature[:80].hex()

        #Hashes each byte of the signature the required number of times.
        for i in range(len(newmessage)-5):
            hashi = signature[80+16*i:80+16*(i+1)]
            result = self.hash_iter(hashi,(255-newmessage[i+5].encode('utf-8')[0])-(255-message[i+5].encode('utf-8')[0])).hex()
            first+=result
        
        #Pads the message with the rest if the public key (equivalent to the null bytes used for padding)
        for i in range(len(first),3584,16):
            first+=public[i:i+16]
        
        #Gets signed-message checksum
        checksum = self.wrap(message)[-16:]
        
        #Gets payload checksum
        newsum = self.wrap(newmessage)[-16:]

        #If the code has reached this far, the newsum bytes are all lower than checksum. Hashes each byte the required number of times.
        for i in range(16): 
            hashi = signature[1792+16*i:1792+16*(i+1)]
            result = self.hash_iter(hashi,(255-newsum[i])-(255-checksum[i])).hex()
            first+=result
        
        return first, newmessage

x = OTS()


#Offline testing of attack. If this block doesn't error out, it has found a (hopefully valid) solution
while True:
    try:
        n = random.randint(0,18104809888552678869)
        s = "My favorite number is "+str(n)+"."
        first, newmessage = x.payload(x.sign(s),x.pub_key,s)
        print(first)
        print(newmessage)
        print(x.sign(newmessage))
    except:
        pass

"""
x.bruteforcer()
"""
