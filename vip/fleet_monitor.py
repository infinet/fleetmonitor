#! /usr/bin/env python
# -*- coding: utf-8 -*-


'''The app lives on end user' machine.
It will query vessel's locations from App Engine and generate a KML file for
Google Earth.
'''


__copyright__ = '2013, Chen Wei <weichen302@gmx.com>'
__version__ = "0.2 2013-04-03"


from Crypto import Random
from PycryptoWrap import Tiger
from PycryptoWrap import CryptoError
from struct import unpack
import os
import platform
import sys
import time
import urllib2


KMLFILE = 'XXX_Fleet_GPS.kml'
scriptpath = os.path.abspath(os.path.dirname(sys.argv[0]))
peerconf = os.path.join(scriptpath, 'peers.conf')
TRACKBUFMAX = 60
EARTH_R = 6371009   # in meters
ERROR_REFRESH_VIPKEYS = 3

if platform.system() == 'Windows':
    info = 'Info in non-english for windows'
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
    res = {'self': {}, 'hq': {}, 'vessels': []}

    for sec in config.sections():
        if 'self' in sec:
            res['self']['priv'] = config.get(sec, 'priv')
            res['self']['name'] = config.get(sec, 'name')

        elif 'hq' in sec:
            res['hq']['url'] = config.get(sec, 'url')
            res['hq']['path'] = config.get(sec, 'path')
            res['hq']['login_path'] = config.get(sec, 'login_path')
            res['hq']['pub'] = config.get(sec, 'pub')
        elif 'vessel' in sec:
            res['vessels'].append(config.get(sec, 'name'))

    return res


class HandshakeError(Exception):
    """ self defined error class"""
    pass


class FleetMonitor(Tiger):
    ''' to negotiate AES key for further commnunication.
    a AES key and HMAC key alos generated for encrypt gps data to be uploaded.
    this AES key set will be encrypted by vip user's public key before send'''
    def __init__(self, device=None, cfg=None):
        self.newpt_count = 0
        self.position = 0
        self.speed_unit = 'Knots'
        self.last_speed = 0
        self.utc_time = ''
        self.heading_degree = 0
        # gapp and Tiger
        self.fetch_srv = norm_address(cfg['hq']['url'] + cfg['hq']['path'])
        self.login_srv = norm_address(cfg['hq']['url'] +
                                                 cfg['hq']['login_path'])
        self.vessel_name = cfg['self']['name']
        self.keysoup = None
        #self.rsa_vippub = self.import_key(open(cfg['vip']['pub']))

        # from ClientHello
        self.key_soup = Random.get_random_bytes(Tiger.RSAOBJ_SIZE - 1)
        self.session_id = Random.get_random_bytes(Tiger.SID_SIZE)
        self.session_key = self.key_soup[:Tiger.SKEY_SIZE]
        self.session_hmac_key = self.key_soup[
                        Tiger.SKEY_SIZE:Tiger.SKEY_SIZE + Tiger.HMACKEY_SIZE]
        self.rsa_hqpub = self.import_key(open(cfg['hq']['pub']))
        self.rsa_priv = self.import_key(open(cfg['self']['priv']))
        self.shared_vipkeys = {}
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
            raise HandshakeError
            return None

        newsession_key_soup = self.rsa_priv.decrypt(server_finish[28:])
        self.session_id = newsession_key_soup[:Tiger.SID_SIZE]
        self.session_key = newsession_key_soup[Tiger.SID_SIZE:
                                            Tiger.SID_SIZE + Tiger.SKEY_SIZE]
        self.session_hmac_key = newsession_key_soup[
                      Tiger.SID_SIZE + Tiger.SKEY_SIZE:
                      Tiger.SID_SIZE + Tiger.SKEY_SIZE + Tiger.HMACKEY_SIZE]

        self.login_okay = True
        self.get_vipkeys()
        self.keysoup = {'s_id': self.session_id,
                        's_key': self.session_key,
                        's_hmac_key': self.session_hmac_key}
                    #    'shared_vipkeys': self.shared_vipkeys}
        #print keysoup

        return self.keysoup

    def onestep(self):
        """load remote pubkey from local file, use RSA to encrypt the aes key
        , then send to server"""
        ctime = time.strftime('%H:%M:%S', time.localtime())
        print ('[{0}] Sending RSA encrypted session key to'
               ' server.....'.format(ctime))
        self.pre_master_secret = Random.get_random_bytes(28)
        msg = '{0:20}'.format(self.vessel_name) + self.pre_master_secret
        #msg = self.vessel_name
        e_aeskeys = self.rsa_hqpub.encrypt(self.key_soup, '')[0]
        return self.session_id + e_aeskeys + self.encrypt_aes(msg,
                                                aeskey=self.session_key,
                                                hmackey=self.session_hmac_key)

    def get_vipkey(self, vessel_name):
        ''' post to gapp, gapp should return a aes keysoup encrypted by vip's
        pulbic key
        '''
        cmd = 'RVIP'

        # a random request id for every request, verify it to prevent replay
        req_id = Random.get_random_bytes(Tiger.REQID_SIZE)
        obfus_key = Random.get_random_bytes(self.SID_SIZE)
        obfus_key += self.xor_obfus(self.session_id, obfus_key)

        msg = req_id + '{0:20}'.format(cmd + vessel_name)
        # the final payload is obfuskey + obfused key + aes(dbreq)
        payload = (obfus_key + self.encrypt_aes(msg,
                                                aeskey=self.session_key,
                                                hmackey=self.session_hmac_key))
        # post to gapp
        e_obj = open_request(self.fetch_srv, payload).read()
        d_msg = self.decrypt_aes(e_obj, aeskey=self.session_key,
                                        hmackey=self.session_hmac_key)
        if req_id != d_msg[:Tiger.REQID_SIZE]:
            print 'Request id mismatch, Possible Replay Attack!'
            return None

        shared_vipkey = d_msg[Tiger.REQID_SIZE:]
        key_soup = self.rsa_priv.decrypt(shared_vipkey)
        vip_session_key = key_soup[:Tiger.SKEY_SIZE]
        vip_session_hmac_key = key_soup[Tiger.SKEY_SIZE:
                                     Tiger.SKEY_SIZE + Tiger.HMACKEY_SIZE]

        self.shared_vipkeys[vessel_name] = {'s_key': vip_session_key,
                                    's_hmac_key': vip_session_hmac_key}
        print 'shared keysoup fetched'

        return 1

    def get_vipkeys(self):
        ''' get the vip key soup from gapp'''
        for vessel in ('enterprise',):
            print 'get shared AES key for %s' % vessel
            self.get_vipkey(vessel)

        return self.shared_vipkeys

    def get_vessel_location(self):
        '''encrypt gps data in vip's aes key, then encrypt again using
        aes, after that, send to gapp'''
        cmd = 'RGPS'

        req_id = Random.get_random_bytes(Tiger.REQID_SIZE)
        obfus_key = Random.get_random_bytes(self.SID_SIZE)
        obfus_key += self.xor_obfus(self.keysoup['s_id'], obfus_key)

        msg = req_id + '{0:20}'.format(cmd)

        # the final payload
        payload = (obfus_key + self.encrypt_aes(msg,
                                            aeskey=self.keysoup['s_key'],
                                            hmackey=self.keysoup['s_hmac_key']))
        # post to gapp
        locations = []
        e_obj = open_request(self.fetch_srv, payload).read()

        dprint('%s receiving new gps data pack' %
              time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime()))
        dprint('total length of received gps data package is %d' % len(e_obj))

        d_msg = self.decrypt_aes(e_obj,
                                aeskey=self.keysoup['s_key'],
                                hmackey=self.keysoup['s_hmac_key'])

        if req_id != d_msg[:Tiger.REQID_SIZE]:
            print 'Request id mismatch, Possible Replay Attack!'
            return None

        content = d_msg[Tiger.REQID_SIZE:]

        for line in content.split('\n'):
            vessel_name = line[:20].strip()
            data = line[20:]
            tmp = self.decode_vessel_location(vessel_name, data)
            if tmp == ERROR_REFRESH_VIPKEYS:
                break
            locations.append(tmp)

        return locations

    def decode_vessel_location(self, vessel_name, e_obj):
        '''every line of data from gapp is formated as
        20 byte           Rest
        -------           ----
        vessel_name       vessel gps data encrypted by shared aes key
        '''
        dprint('decode location of %s' % vessel_name)
        shared_vipkey = self.shared_vipkeys[vessel_name]
        dprint('receiving and decoding vessel gps data pack')
        dprint(vessel_name)
        dprint('len of encrypted gps data pack = %d' % len(e_obj))
        try:
            gpsdata = self.decrypt_aes(e_obj,
                                    aeskey=shared_vipkey['s_key'],
                                    hmackey=shared_vipkey['s_hmac_key'])
        except CryptoError:

            print ('CryptoError! It might be the AES key has been changed by '
                   'the vessel. Refresh shared AES key in 5 seconds')

            time.sleep(5)
            self.get_vipkeys()
            return ERROR_REFRESH_VIPKEYS

        return (vessel_name, self.gpsunpack(gpsdata))

    def gpsunpack(self, gpsdata):
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
        ungps = unpack('<iihLLL', gpsdata)
        res = {'lon': ungps[0] / 1000000.0,
               'lat': ungps[1] / 1000000.0,
               'heading': ungps[2],
               'speed_knots': ungps[3] / 1000.0,
               'tgps': time.strftime('%Y-%m-%d %H:%M:%S',
                                     time.gmtime(ungps[4])),
               'tmsg': time.strftime('%Y-%m-%d %H:%M:%S',
                                     time.gmtime(ungps[5]))}
        return res

    def kml_gen(self, vessels_data):
        ''' generate kml for google earth '''
        for vessel, gpsdata in vessels_data:
            print 'Generating KML for %s' % vessel
            print gpsdata
            speed = gpsdata['speed_knots']
            latitude = gpsdata['lat']
            longitude = gpsdata['lon']
            heading = gpsdata['heading']
            time_str = gpsdata['tgps']

            output = '''<?xml version="1.0" encoding="UTF-8"?>
        <kml xmlns="http://earth.google.com/kml/2.0">
        <Placemark>
            <name>%s - %s knot,heading %s %s</name>
            <description>Realtime GPS feeding</description>
            <LookAt>
                <longitude>%s</longitude>
                <latitude>%s</latitude>
            </LookAt>
            <Point>
                <coordinates>%s,%s,%s</coordinates>
            </Point>
        </Placemark>
        </kml>''' % (vessel, speed, heading, time_str,
                     longitude, latitude, longitude, latitude, 0)
            kmlfp = open(KMLFILE, 'w')
            kmlfp.write(output)
            kmlfp.close()

    def run(self):
        try:
#             session = gps.gps( host=self.host, port=self.port)
            # session.stream(gps.WATCH_ENABLE|gps.WATCH_NEWSTYLE)
            while True:
                # get gps data pack from gapp
                vessel_locations = self.get_vessel_location()
                if vessel_locations:
                    self.kml_gen(vessel_locations)
                time.sleep(2)
                # generate kml
                pass
        except StopIteration:
            print 'stop iteration'
        except KeyboardInterrupt:
            print 'bye'


def main():
    runtime_cfg = get_config()
    conn = FleetMonitor(cfg=runtime_cfg)
    newkeysoup = conn.onestep_login()
    # print runtime_cfg
    # print newkeysoup
    print '***********XXX Fleet Monitor**********'
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
    conn.run()
    # good the keys for next step are all set


if __name__ == '__main__':
    main()
