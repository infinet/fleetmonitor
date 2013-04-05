#! /usr/bin/env python
# -*- coding: utf-8 -*-

'''The app lives on the vessel.
It reads gps info from gpsd, pack / encrypt, then send to App Engine.
'''


__copyright__ = '2013, Chen Wei <weichen302@gmx.com>'
__version__ = "0.2 2013-04-03"


from Crypto import Random
from PycryptoWrap import Tiger
from math import sin, cos, asin, sqrt, radians
from socket import error as SocketError
from struct import pack
import gps
import os
import platform
import sys
import time
import urllib2


scriptpath = os.path.abspath(os.path.dirname(sys.argv[0]))
peerconf = os.path.join(scriptpath, 'peers.conf')
TRACKBUFMAX = 60
EARTH_R = 6371009   # in meters

if platform.system() == 'Windows':
    info = 'Info in chinese for windows'
    info = info.decode('utf-8').encode(sys.getfilesystemencoding())

    def dprint(msg):
        """print colorfule debug message"""
        print 'debug: ' + str(msg)
else:
    info = 'Start serving...'
    import console

    def dprint(msg):
        """print colorfule debug message"""
        print console.colorize('red', 'debug: ' + str(msg))


def earthdistance(c1, c2):
    '''given two WGS84 coordinates in complex number, calculate distance,
    use haversine formula for small distance
    http://en.wikipedia.org/wiki/Great-circle_distance
    '''
    delta_lon = radians(c1.real - c2.real)
    delta_lat = radians(c1.imag - c2.imag)
    theta = 2 * asin(sqrt(sin(delta_lat / 2) ** 2 +
     cos(radians(c1.imag)) * cos(radians(c2.imag)) * sin(delta_lon / 2) ** 2))
    return theta * EARTH_R


def norm_address(url):
    """ensure the url is in correct form"""
    url = url.lower()
    if url.startswith('http'):
        return url
    else:
        return 'http://' + url


def open_request(path, data):
    '''request handle
    Args:
        path: the request URL
        data: POST method payload
        proxies: a dict in form of {'http': xx, 'https': yy}
    Return:
        an opener'''
    request = urllib2.Request(path)
    request.add_data(data)
    request.add_header('Content-Type', 'application/octet-stream')
    request.add_header('User-Agent',
                       'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)')
    opener = urllib2.build_opener()
    urllib2.install_opener(opener)
    # The HTTP request will be a POST instead of a GET when the data
    # parameter is provided, http://docs.python.org/library/urllib2
    return urllib2.urlopen(request)


def get_config():
    '''parse the configure file, return a dictionary of preconfigured
    shapes and locations'''
    import ConfigParser
    config = ConfigParser.ConfigParser()
    config.readfp(open(peerconf))
    res = {'self': {}, 'hq': {}, 'vip': {}, 'gpsd-server': {}}

    for sec in config.sections():
        if 'self' in sec:
            res['self']['priv'] = config.get(sec, 'priv')
            res['self']['name'] = config.get(sec, 'name')

        elif 'hq' in sec:
            res['hq']['url'] = config.get(sec, 'url')
            res['hq']['path'] = config.get(sec, 'path')
            res['hq']['login_path'] = config.get(sec, 'login_path')
            res['hq']['pub'] = config.get(sec, 'pub')
        elif 'vip' in sec:
            res['vip']['pub'] = config.get(sec, 'pub')
        elif 'gpsd-server' in sec:
            res['gpsd-server']['host'] = config.get(sec, 'host')
            res['gpsd-server']['port'] = config.get(sec, 'port')

    return res


class HandshakeError(Exception):
    """ self defined error class"""
    pass


class ClientHello(Tiger):
    ''' to negotiate AES key for further commnunication.
    a AES key and HMAC key alos generated for encrypt gps data to be uploaded.
    this AES key set will be encrypted by vip user's public key before send'''

    def __init__(self, cfg=None):

        self.fetch_srv = norm_address(cfg['hq']['url'] +
                                                 cfg['hq']['path'])
        self.login_srv = norm_address(cfg['hq']['url'] +
                                                 cfg['hq']['login_path'])
        self.vessel_name = cfg['self']['name']
        self.key_soup = Random.get_random_bytes(Tiger.RSAOBJ_SIZE - 1)
        self.session_id = None
        self.session_key = self.key_soup[:Tiger.SKEY_SIZE]
        #self.iv = Random.get_random_bytes(Tiger.IV_SIZE)
        self.session_hmac_key = self.key_soup[
                        Tiger.SKEY_SIZE:Tiger.SKEY_SIZE + Tiger.HMACKEY_SIZE]

        self.rsa_vippub = self.import_key(open(cfg['vip']['pub']))
        self.rsa_hqpub = self.import_key(open(cfg['hq']['pub']))
        self.rsa_priv = self.import_key(open(cfg['self']['priv']))
        self.login_okay = False

    def onestep_login(self):
        """Send client pubkey with aes key to server in one step, the message
        formatted as:
        session_id + RSA(aes keys) + AES(client_pubkey + sig)
        """
        try:
            client_finish = open_request(self.login_srv,
                                         self.onestep()).read()
        except HandshakeError:
            return None
        server_finish = self.decrypt_aes(client_finish,
                                      aeskey=self.session_key,
                                      hmackey=self.session_hmac_key)

        if self.pre_master_secret != server_finish[:28]:
            print 'Fatal Error, Pre Master Secret mismatch, handshake failed!'
            return None

        newsession_key_soup = self.rsa_priv.decrypt(server_finish[28:])

        self.session_id = newsession_key_soup[:Tiger.SID_SIZE]
        self.session_key = newsession_key_soup[Tiger.SID_SIZE:
                                            Tiger.SID_SIZE + Tiger.SKEY_SIZE]
        self.session_hmac_key = newsession_key_soup[
                      Tiger.SID_SIZE + Tiger.SKEY_SIZE:
                      Tiger.SID_SIZE + Tiger.SKEY_SIZE + Tiger.HMACKEY_SIZE]

        # TODO: send vipkey to fetch server instead
        vipkey_sent = open_request(self.login_srv, self.vipkey()).read()
        vipack = self.decrypt_aes(vipkey_sent,
                                  aeskey=self.session_key,
                                  hmackey=self.session_hmac_key)
        keysoup = None
        if 'VIPKeyAcknowledge' in vipack:
            self.login_okay = True
            keysoup = {'s_id': self.session_id,
                       's_key': self.session_key,
                       's_hmac_key': self.session_hmac_key,
                       'vip_key': self.vip_session_key,
                       'vip_hmac_key': self.vip_session_hmac_key}

        return keysoup

    def onestep(self):
        """load remote pubkey from local file, use RSA to encrypt the aes key
        , then send to server"""
        ctime = time.strftime('%H:%M:%S', time.localtime())
        print ('[{0}] Sending RSA encrypted session key to'
               ' server.....'.format(ctime))

        # add more randomness by padding the msg to 3 * 128 bit = 3 AES block,
        # it still need another padding after zip though. It also serve to
        # verify server's acknowledge message which should include the
        # pre_master_secret
        self.pre_master_secret = Random.get_random_bytes(28)
        msg = '{0:20}'.format(self.vessel_name) + self.pre_master_secret

        e_aeskeys = self.rsa_hqpub.encrypt(self.key_soup, '')[0]
        print msg
        return e_aeskeys + self.encrypt_aes(msg,
                                                aeskey=self.session_key,
                                                hmackey=self.session_hmac_key)

    def vipkey(self):
        ''' generate key soup for vip, encrypted with vip's public key, prefix
        it with 20 byte long vessel name, then encrypt and send to gapp

        payload:
        20 byte            the rest
        -------            --------
        vessel name        Public key encrypted key soup

        '''

        key_soup = Random.get_random_bytes(Tiger.RSAOBJ_SIZE - 1)
        self.vip_session_key = key_soup[:Tiger.SKEY_SIZE]
        self.vip_session_hmac_key = key_soup[Tiger.SKEY_SIZE:
                                         Tiger.SKEY_SIZE + Tiger.HMACKEY_SIZE]

        payload = ('{0:20}'.format(self.vessel_name) +
                                    self.rsa_vippub.encrypt(key_soup, '')[0])
        # the keyword ChickenRib is used to identify vipkey package
        # dprint('hash of hmac key is %s' %
                              # hashlib.md5(self.session_hmac_key).hexdigest())

        payload = (self.session_id + 'ChickenRib' +
                self.encrypt_aes(payload, aeskey=self.session_key,
                                         hmackey=self.session_hmac_key))
        print 'vip-vessel share aes keysoup generated'
        return payload


class Main(Tiger):
    def __init__(self, host='localhost', port='2947', device=None, cfg=None,
                keysoup=None):
        self.host = host
        self.port = port
        self.device = device
        self.newpt_count = 0
        self.position = 0
        self.track = [complex(0, 0)] * TRACKBUFMAX
        self.track_indx = 0
        self.track_rewind = False
        self.track_refresh_cnt = 0
        self.speed_unit = 'Knots'
        self.speed_knots = 0
        self.last_speed = 0
        self.utc_time = ''
        self.heading_degree = 0

        # gapp and Tiger
        self.fetch_srv = norm_address(cfg['hq']['url'] + cfg['hq']['path'])
        self.vessel_name = cfg['self']['name']
        self.keysoup = keysoup
        #self.rsa_vippub = self.import_key(open(cfg['vip']['pub']))

    def post2gapp(self):
        '''encrypt gps data in vip's aes key, then encrypt again using
        aes, after that, send to gapp'''
        gps_data = self.gpspackgen()

        # encrypt it by the aes key shared with vip, prefix with 20 byte long
        # vessel name
        e_vip = ('{0:20}'.format(self.vessel_name) +
                   self.encrypt_aes(gps_data, aeskey=self.keysoup['vip_key'],
                                 hmackey=self.keysoup['vip_hmac_key']))

        # A fixed session_id is too obvious, so use a random string XOR with it
        # to make it hard to see pattern
        obfus_key = Random.get_random_bytes(self.SID_SIZE)
        obfus_key += self.xor_obfus(self.keysoup['s_id'], obfus_key)

        # the final payload
        payload = (obfus_key +
                   self.encrypt_aes(e_vip,
                                    aeskey=self.keysoup['s_key'],
                                    hmackey=self.keysoup['s_hmac_key']))
        # post to gapp
        try:
            req = open_request(self.fetch_srv, payload).read()
            print req
        except urllib2.HTTPError:
            print 'http error'

    def gpspackgen(self):
        '''generate a package for vip user
        format:
        4 byte    signed integer    lon x 1,000,000
        4 byte    signed integer    lat x 1,000,000
        2 byte    signed integer    heading in degree
        4 byte    unsigned          speed in knots x 1,000
        4 byte    unsigned          time of gps reading
        4 byte    unsigned          time of message generated

        the output is 22 byte

        '''
        m1 = 1000000
        res = pack('<iihLLL', int(self.position.real * m1),
                   int(self.position.imag * m1),
                   self.heading_degree,
                   self.speed_knots,
                   self.gps_time,
                   int(time.time()))
        return res

    def update_speed(self, data):
        '''put image exporting control here, use a timer'''
        if hasattr(data, 'time'):
            # data.time is a unicode string 2013-03-25T21:20:27.000Z
            # gps_time is a integer in seconds from epoch
            if len(data.time) == 24:
                tstr = data.time[:19]
            elif len(data.time) == 19:
                tstr = data.time
            self.gps_time = int(time.mktime(time.strptime(tstr,
                                                      '%Y-%m-%dT%H:%M:%S')))

        if hasattr(data, 'speed'):
            # the speed send to vip is knots x 1000
            self.speed_knots = int(data.speed * gps.MPS_TO_KNOTS * 1000)
        if hasattr(data, 'track'):
            self.heading_degree = int(data.track)
        if hasattr(data, 'lon') and hasattr(data, 'lat'):
            pos = complex(float(data.lon), float(data.lat))
            self.newpt_count += 1
            distance = earthdistance(pos,
                             self.track[self.track_indx - 1])
            print 'distance is %s' % distance
            #print '\ndistance between points %f m' % distance
            # update position if distance greater than 10m, or every
            # 20 gps reading received
            if (self.newpt_count > 0) or (distance > 0):

                # push the gps data to gapp
                self.post2gapp()

                self.newpt_count = 0
                self.position = pos
                if self.track_indx < TRACKBUFMAX:
                    track_indx = self.track_indx
                    self.track_indx += 1
                    print 'track index is %d' % self.track_indx
                else:
                    # reache the end of track buffer, rewind
                    print 'i am here, rewinding'
                    track_indx = self.track_indx = 0
                    self.track_rewind = True
                self.track[track_indx] = pos

    def run(self):
        try:
            session = gps.gps(host=self.host, port=self.port)
            session.stream(gps.WATCH_ENABLE | gps.WATCH_NEWSTYLE)

            while True:
                rpt = session.next()
                if rpt['class'] == 'TPV':
                    self.update_speed(rpt)
        except StopIteration:
            print 'gpsd has stopped, please restart gpsd, retry in 5 seconds'
            self.run()
        except KeyboardInterrupt:
            print 'bye'
        except gps.client.json_error:
            print 'Looks like gpsd is not ready, retry in 5 seconds'
            time.sleep(5)
            self.run()
        except SocketError:
            print 'Is gpsd running? retry in 5 seconds'
            time.sleep(5)
            self.run()


def main():
    runtime_cfg = get_config()
    clt_conn = ClientHello(cfg=runtime_cfg)
    newkeysoup = clt_conn.onestep_login()
    # print runtime_cfg
    # print newkeysoup
    print '***********XXX Fleet GPS data uploader**********'
    print ''
    print '--------------------------------------------'
    print 'Logging into %s' % runtime_cfg['hq']['url']
    if not newkeysoup:
        print 'Authentication failed.'
    else:
        print 'Authentication successful.'
        print ''
        print ''
        print info

    Main(host=runtime_cfg['gpsd-server']['host'],
            port=runtime_cfg['gpsd-server']['port'],
            keysoup=newkeysoup,
            cfg=runtime_cfg).run()
    # good the keys for next step are all set


if __name__ == '__main__':
    main()
