#!/usr/bin/env python
# -*- coding: utf-8 -*-

'''The app lives on Google App Engine.
It will accept pushed gps data from vessel, and answer request from end users.
'''


__copyright__ = '2013, Chen Wei <weichen302@gmx.com>'
__version__ = "0.2 2013-04-03"


import os
import sys
from struct import pack, unpack
import base64
import logging
import wsgiref.handlers
from google.appengine.ext import db
from google.appengine.api import memcache
#from google.appengine.api import urlfetch_errors
#from google.appengine.runtime import DeadlineExceededError
from google.appengine.ext import webapp
from PycryptoWrap import Tiger
import hashlib


scriptpath = os.path.abspath(os.path.dirname(sys.argv[0]))
peerconf = os.path.join(scriptpath, 'peers.conf')
VESSELS = ('enterprise',)
TEST_PAGE = ('<HTML><HEAD><TITLE>Test Page</TITLE></HEAD>'
             '<BODY><H1>It Worked!</H1>'
             'If you can see this, then your installation was successful.'
             '<P></BODY></HTML>')


class StoreKey(db.Model):
    """the database for storing session_id and its correspond session_keys"""
    s_id = db.ByteStringProperty()
    s_key_hmackey = db.BlobProperty()
    date = db.DateTimeProperty(auto_now_add=True)


class VIPKey(db.Model):
    """the database for storing session_id and its correspond session_keys"""
    vessel_name = db.ByteStringProperty()
    vip_key = db.BlobProperty()
    date = db.DateTimeProperty(auto_now_add=True)


class GPSData(db.Model):
    """the database for storing gpsdata for given vessel"""
    vessel_name = db.ByteStringProperty()
    gpsdata = db.BlobProperty()
    vessel_time_stamp = db.IntegerProperty()
    date = db.DateTimeProperty(auto_now_add=True)


def dprint(msg, prefix='Debug: '):
    """print debug info on SDK console"""
    logging.info(prefix + msg)


def get_config():
    '''parse the configure file, return a dictionary of preconfigured
    shapes and locations'''
    import ConfigParser
    config = ConfigParser.ConfigParser()
    config.readfp(open(peerconf))

    res = {'self': {'priv': ''},
           'vessels': {}}

    for sec in config.sections():
        if 'self' in sec:
            res['self']['priv'] = config.get(sec, 'priv')

        elif 'vessel' in sec:
            vname = config.get(sec, 'name')
            res['vessels'][vname] = config.get(sec, 'pub')

    return res


def get_session_key(sess_id):
    """Get the session_key from memcache, if not found, retrive it from GAE
    datastore.
    Args:
        sess_id: the client's session id to look up
    Return:
        {session_id: key, hmac_id: hmac_key}"""
    s_key_hmackey = memcache.get(sess_id)
    if not s_key_hmackey:
        stored_keys = db.GqlQuery('SELECT * FROM StoreKey WHERE s_id = :1',
                                  base64.b64encode(sess_id)).get()

        s_key_hmackey = stored_keys.s_key_hmackey
        if not memcache.set(key=sess_id, value=s_key_hmackey):
            logging.error('session keys Memcache set failed.')

    sess_key = s_key_hmackey[:Tiger.SKEY_SIZE]
    hmac_key = s_key_hmackey[Tiger.SKEY_SIZE:Tiger.SKEY_SIZE +
                                                    Tiger.HMACKEY_SIZE]

    return {'session_key': sess_key, 'hmac_key': hmac_key}


def get_shared_vipkey(vessel_name):
    '''Get the shared vip aes key, which is encrypted by public key, from
    memcache.

    Args:
        vessel_name: the vessel name to look up
    Return:
        the public key encrypted object
        '''

    shared_vipkey = memcache.get(vessel_name)
    if not shared_vipkey:
        req = db.GqlQuery('SELECT * '
                                    'FROM VIPKey '
                                    'WHERE vessel_name = :1 '
                                    'ORDER BY date DESC LIMIT 1',
                                    vessel_name).get()
        shared_vipkey = req.vip_key
        if not memcache.set(key=vessel_name, value=shared_vipkey):
            logging.error('vip-vessel shared AES keys Memcache set failed.')

    return shared_vipkey


def get_gpsdata(vessel_name):
    '''Get the shared vip aes key, which is encrypted by public key, from
    memcache.

    Args:
        vessel_name: the vessel name to look up
    Return:
        the public key encrypted object
        '''
    gps_vip_pack_id = 'gpsdata-' + vessel_name
    gps_vip_pack = memcache.get(gps_vip_pack_id)
    if not gps_vip_pack:
        res = db.GqlQuery('SELECT * '
                                    'FROM GPSData '
                                    'WHERE vessel_name = :1 '
                                    'ORDER BY date DESC LIMIT 1',
                                    vessel_name).get()
        if res:
            gps_vip_pack = res.gpsdata
        else:
            gps_vip_pack = None
        if not memcache.set(key=gps_vip_pack_id, value=gps_vip_pack):
            logging.error('gps data pack Memcache set failed')

    return gps_vip_pack


def get_vessel_time_stamp(vessel_name):
    '''Get the time stamp for last gps data pack vessel posted
    Args:
        vessel_name: the vessel name to look up
    Return:
        the timestamp in integer
        '''
    ts_id = 'ts-' + vessel_name
    timestamp = memcache.get(ts_id)
    if not timestamp:
        res = db.GqlQuery('SELECT * '
                                    'FROM GPSData '
                                    'WHERE vessel_name = :1 '
                                    'ORDER BY date DESC LIMIT 1',
                                    vessel_name).get()
        if res:
            timestamp = res.vessel_time_stamp
        else:
            timestamp = 0
        memcache.set(key=ts_id, value=timestamp)

    return timestamp


class MainHandler(webapp.RequestHandler, Tiger):

    def error_page(self, reqid, status, description):
        '''Generate the Error Page'''
        self.response.headers['Content-Type'] = 'application/octet-stream'
        content = []
        content.append('HTTP/1.1 %d %s' % (status, description))
        content.append('Content-Type: text/html')
        content.append('')
        content.append('<h1>Fleet Server Error</h1><p>Error Code:'
                       '%d</p><p>%s</p>' % (status, description))
        self.response.out.write(self.encrypt_aes(reqid +
                                                 '\r\n'.join(content)))

    def plain_error(self, status):
        '''Generate the unencrypted Error Page'''
        self.response.headers['Content-Type'] = 'application/octet-stream'
        content = []
        content.append('HTTP/1.1 %d %s' % (status, 'Internal Error'))
        content.append('Content-Type: text/html')
        content.append('')
        content.append('<h1>Fleet Server Error</h1><p>Error Code:'
                       '%d</p>' % status)
        self.response.out.write('\r\n'.join(content))

    def post(self):
        c_req = self.request.body

        # the session_id has been obfuscated by XOR
        obfus_key = c_req[:Tiger.SID_SIZE]
        session_id = self.xor_obfus(c_req[Tiger.SID_SIZE:Tiger.SID_SIZE * 2],
                                                                    obfus_key)
        res = get_session_key(session_id)

        if not res:
            # the session key no longer in memcach, send a self-defined http
            # error 521 back to client
            # 512 - 598 error code is available for custom
            dprint('seesion key not found')
            self.plain_error(521)
            return

        # format of the payload
        # 4 byte    16 byte         rest
        # ------    -----------     ----
        # CMD       vessel name     data
        e_vip = self.decrypt_aes(c_req[Tiger.SID_SIZE * 2:],
                                aeskey=res['session_key'],
                                hmackey=res['hmac_key'])
        req_id = e_vip[:Tiger.REQID_SIZE]
        cmd = e_vip[Tiger.REQID_SIZE: Tiger.REQID_SIZE + 4]
        vessel_name = e_vip[Tiger.REQID_SIZE + 4: Tiger.REQID_SIZE+20].strip()
        data = e_vip[Tiger.REQID_SIZE + 20:]
        if cmd == 'RVIP':  # vip request vessel-vip AES key
            # return vip aes keysoup, which is encrypted by vip public key
            dprint('the user is retrieving shared vip-vessel aes keys')
            aes_payload = req_id + get_shared_vipkey(vessel_name)
        elif cmd == 'RGPS':
            # vip looking for vessel's gps data pack
            content = []
            for v_name in VESSELS:
                gps_vip_pack = get_gpsdata(v_name)
                len_gps_pack = len(gps_vip_pack)

                if gps_vip_pack:
                    #content.append('{0:20}'.format(v_name) + gps_vip_pack)
                    content.append(pack('<L16s', len_gps_pack, v_name)
                                   + gps_vip_pack)

            aes_payload = req_id + ''.join(content)
            # the payload is 104 long with one vessel, gps data pack is 68
            dprint('gpsdata payload is %d long' % len(aes_payload))
        elif cmd == 'PGPS':
            # received vessel's gps data pack
            #vessel_name = msgheader
            gps_vip_pack_id = 'gpsdata-' + vessel_name
            gps_vip_pack = data
            timestamp = unpack('<L', req_id[:4])[0]
            if timestamp <= get_vessel_time_stamp(vessel_name):
                dprint('Replay attack? Somebody want inject stale info')
                # replay attack? abort here
                return

            gpsdatastore = GPSData(vessel_name=vessel_name,
                                   vessel_time_stamp=timestamp,
                                   gpsdata=gps_vip_pack)
            gpsdatastore.put()
            memcache.set(key=gps_vip_pack_id, value=gps_vip_pack)
            memcache.set(key='ts-%s' % vessel_name, value=timestamp)

            dprint('gps data pack received and saved to memcache')
            aes_payload = 'PGPS OKAY'
        elif cmd == 'PVIP':
            '''Received a new aes key for vip users, this key is encrypted with
            vip user's public key, it will be stored in gapp datastore. All gps
            data of vessel will be encrypted with this aes key before upload.

            The respond has one word VIPKeyAcknowledge, which also encrypted in
            AES.'''

            e_vipkeys = data

            vipkeystore = VIPKey(vessel_name=vessel_name, vip_key=e_vipkeys)
            vipkeystore.put()
            memcache.set(key=vessel_name, value=e_vipkeys, time=86400)
            aes_payload = 'PVIP OKAY'

        resp = self.encrypt_aes(aes_payload,
                                aeskey=res['session_key'],
                                hmackey=res['hmac_key'])
        self.response.headers['Content-Type'] = 'application/octet-stream'
        self.response.out.write(resp)

    def get(self):
        self.response.headerlist = [('Content-type', 'text/html')]
        self.response.out.write(TEST_PAGE)
        return


def main():
    handler = MainHandler
    application = webapp.WSGIApplication([('/', handler)])
    wsgiref.handlers.CGIHandler().run(application)

if __name__ == '__main__':
    main()
