#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''provide a easy and unified interface for PyCrypto.'''


__all__ = ['Tiger']
__copyright__ = '2013, Chen Wei <weichen302@gmx.com>'
__version__ = "0.2 2013-04-03"


import os
import zlib
import hashlib
import hmac
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.PublicKey import RSA


class CryptoError(Exception):
    """the custom exception"""


class Tiger:
    """Hu Fu, the military token used by ancient Chinese army, makes a perfect
    name for a crypto class.

    This class contain essential AES and RSA. Keys used for encrypt, decrypt,
    and HMAC hash are passed around as class attributes.

    Attribute:
        block_size: the iv size
        session_key: a random key generated each session, used by AES
        session_hmac_key: a random 32 bytes key for HMAC digest
        session_id: a random generated 8 bytes long string, used by remote host
                    to identified the current client and look up correspond keys
                    in GAE memcache and datastore
    Methods:
        calc_hmac:
        encrypt_aes: take plain message as input
        decrypt_aes: take crypted message as input
        load_rsa_key: load a pickled rsa key object for string or file
        pretty_fingerprint: print a nice looking pub/private key fingerprint
    """
    BLOCK_SIZE = IV_SIZE = 16
    SID_SIZE = 8
    SKEY_SIZE = 16
    HMACKEY_SIZE = 32
    REQID_SIZE = 16
    RSAKEY_SIZE = 2048
    RSAOBJ_SIZE = RSAKEY_SIZE / 8

    def __init__(self):
        self.session_key =  ''
        self.session_hmac_key =  ''
        self.rsa_priv = None
        self.rsa_pub = None

    def xor_obfus(self, msg, key):
        """Use XOR to obfuscate session id"""
        return ''.join(chr(ord(x) ^ ord(y)) for (x,y) in zip(msg, key))

    def calc_hmac(self, hmackey, msg):
        '''
        use 32 byte hmackey and sha256. In HMAC, the recommended length of hmac
        key is at least the output length of hash function. Sha256 returns a 32
        bytes long hash, trunct it to 20 byte.

        Truncting the output "has advantages (less information on the hash
        result available to an attacker) and disadvantages (less bits to
        predict for the attacker)"  - RFC2104

        msg: the message
        '''
        return hmac.new(hmackey, msg, hashlib.sha256).digest()[:20]

    def encrypt_aes(self, ptxt, aeskey=None, hmackey=None):
        """
        iv length should be the same as block size, which is 128 bit(16 bytes),
        a HMAC is calculated on (iv + cypted_text), the random key for HMAC is
        32 bytes long, change for each new session. The output is constructed
        as: iv + crypted_text + HMAC
        Args: ptxt should be plaintext"""

        # TODO change to Random.get_random_bytes
        #iv = Random.get_random_bytes(self.IV_SIZE)
        # debug
        iv = os.urandom(self.IV_SIZE)
        aes_cipher = AES.new(aeskey, AES.MODE_CBC, iv)
        c_text = aes_cipher.encrypt(pad(zlib.compress(ptxt), self.BLOCK_SIZE))
        c_hmac = self.calc_hmac(hmackey, iv + c_text) # 20 bytes long
        return iv + c_text + c_hmac

    def decrypt_aes(self, ctxt, aeskey=None, hmackey=None):
        """
        the first 16 bytes from the crypted text is the iv, the last 20 bytes
        of c is HMAC, the actual message is in between.
        Args: ctxt as crypted text"""
        iv = ctxt[:self.IV_SIZE]
        c_hmac = ctxt[-20:]
        c_text = ctxt[self.IV_SIZE:-20]
        if c_hmac != self.calc_hmac(hmackey, ctxt[:-20]):
            raise CryptoError('HMAC mismatch')
        aes_decipher = AES.new(aeskey, AES.MODE_CBC, iv)
        decrypted = unpad(aes_decipher.decrypt(c_text), self.BLOCK_SIZE)
        return zlib.decompress(decrypted)

    def pretty_fingerprint(self, msg):
        """use sha1 hash to represent fingerprint in an easy read way"""
        hash_str = hashlib.sha1(msg).hexdigest()
        output = []
        while len(hash_str) > 0:
            output.append(hash_str[:4])
            hash_str = hash_str[4:]
        return ' '.join(output).upper()

    def import_key(self, pem):
        """load a PEM format key(Public or Private) from file
        Arg: pem a file object or a string
        Return: a RSA object"""
        if type(pem) == type('i am string'):
            res = RSA.importKey(pem)
        else:
            res = RSA.importKey(pem.read())
        return res

    def load_authorized_keys(self):
        """Load saved rsa public keys from file, return a set of public keys"""
        fkey = open('authorized_keys')
        #kblc_start = '-----BEGIN PUBLIC KEY-----'
        kblc_end = '-----END PUBLIC KEY-----\n'
        cur_key, res = [], []
        for line in fkey:
            cur_key.append(line)
            if line == kblc_end:
                res.append(''.join(cur_key))
                cur_key = []
        return set(res)

    def gen_rsa_keypair(self, filepub, filepriv):
        """generate a 2048 bit long RSA public/private keypair, the pub/priv
        keys in pycrypto 2.0.1 are RSA object, which can not be exported
        directly, to export it, the key are converted to string by pickle, then
        write to disk.  the key file on disk can be read back by pickle, with
        one restriction: the version of pycrypto must be the same.

        New in Pycrypto 2.3: the public/private key can be export as text
        format by exportKey, then read back by importKey. The encrypt output
        of RSA has the same size of the key 1024 bits RSA key has the security
        level of 80 bits AES key, 3072 bits RSA key has the security level of
        128 bits.

        """

        fpub = open(filepub, 'w')
        fpriv = open(filepriv, 'w')
        print 'Generating {0} bit pub/priv keypair...'.format(self.RSAKEY_SIZE)
        priv_key = RSA.generate(self.RSAKEY_SIZE, Random.new().read)
        pub_key = priv_key.publickey()

        print '\nWriting private key to %s' % filepriv
        fpriv.write(priv_key.exportKey())
        print 'Writing public key to %s' % filepub
        fpub.write(pub_key.exportKey()+ '\n')
        print '{0} bit pub/priv keypair generated'.format(self.RSAKEY_SIZE)


def pad(pcon,  block_size):
    """AES has fixed block size of 128 bit, key size 128|192|256 bit"""
    assert 1 <= block_size <= 256
    pad_len = block_size - len(pcon) % block_size
    return pcon + chr(pad_len) * pad_len


def unpad(upcon, block_size):
    """With reference to RFC 5652 6.3"""
    assert 1 <= block_size <= 256
    if len(upcon) == 0 or upcon[-1] < len(upcon):
        raise CryptoError('Padding error.')
    return upcon[:-ord(upcon[-1])]


def test_aes():
    """use AES to encrypt & decrypt a string"""
    tiger = Tiger()
    tiger.session_key = '1234567890123456'
    tiger.session_hmac_key = 'abcdefghijabcdefghijabcdefghij01'
    msg = 'this is a test'
    e_msg = tiger.encrypt_aes(msg, aeskey=tiger.session_key ,
                             hmackey=tiger.session_hmac_key)
    d_msg = tiger.decrypt_aes(e_msg)
    print 'The original message is: \n{0}\n'.format(msg)
    print 'The encrypted message is: \n{0}\n'.format(e_msg)
    print 'Decrypted messages is: \n{0}'.format(d_msg)


def test_rsa():
    """generate a test key pair, write to disk and read back"""
    tiger = Tiger()
    #tiger.gen_rsa_keypair()
    print '\nLoad the private key'
    rsa_priv = tiger.import_key(open('id_rsa'))

    print '\nImport public key in PEM format'
    rsa_pub = tiger.import_key(open('id_rsa.pub'))
    print 'Public key imported'
    p_msg = 'This is a plaintext testing message'
    print '\n{0}'.format(p_msg)
    c_msg = rsa_pub.encrypt(p_msg, '')[0]
    print c_msg
    d_msg = rsa_priv.decrypt(c_msg)
    print '\nThe decrypted message is:\n{0}'.format(d_msg)


if __name__ == "__main__":
#    test_aes()
#    t = Tiger()
#    t.gen_rsa_keypair()
    test_rsa()
