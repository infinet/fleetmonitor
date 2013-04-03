#!/usr/bin/env python
# -*- coding: utf-8 -*-

'''Generate or re-generate RSA keypairs for client and server'''

import os
from PycryptoWrap import Tiger


scriptpath = os.path.split(os.path.realpath( __file__ ))[0]
#scriptpath = os.path.split(scriptpath)[0]
ID_RSA = os.path.join(scriptpath, 'id_rsa')
ID_RSA_PUB = os.path.join(scriptpath, 'id_rsa.pub')


def main():
    tiger = Tiger()
    print '\nGenerating pub/private keypair...'
    tiger.gen_rsa_keypair(ID_RSA_PUB, ID_RSA)

    print 'Public key saved to %s' % ID_RSA_PUB
    print 'Private key saved to %s' % ID_RSA


if __name__ == "__main__":
    main()

