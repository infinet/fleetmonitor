Fleet Monitor
=============

Fleet Monitor is a Google Earth KML generator for Marine Companies to monitor
their worldwide fleet position status. On the vessel side, a userland script
read vessel location from gpsd, then upload that location to Google AppEngine
for temporary storage. A script on end user's machine can fetch vessel's
location from Google AppEngine, then generate a KML file for display in Google
Earth.

There are many similar products available, some are paid, some are free, but
with noticeable delay from days to weeks. The Fleet Monitor is a proof of
concept that better fleet monitoring can be achieved by combine free or
opensource software / service.


License
=======

This software (Fleet Monitor) is released under the terms and conditions of the
BSD License, a copy of which is include in the file COPYRIGHT.

Design
======

The communications between vessel/google earth user and Google AppEngine is
protected by 128bit AES encryption.

Public Key is used to exchange the random generated AES key. The peers have
each other’s Public Key.

The gps data of vessel is upload to Google AppEngine before it can be fetched
by end users (Google Earth). To ensure confidentiality and data integrity,
those gps data is encrypted with another set of AES key which only share
between the Google Earth User and the vessel. Vessel A will NOT know Vessel B’s
location because it does have the AES key use between Vessel B and end user.
Again, Public Key is used to exchange the AES key.

A XML file contains vessels locations is generated periodically on the end
user’s computer after receive & decrypt the gps data. Google Earth reads and
displays the placemarks in this XML file.

*format of gps data package*
4 byte    signed integer    lon x 1,000,000
4 byte    signed integer    lat x 1,000,000
2 byte    signed integer    heading in degree
4 byte    unsigned          speed in knots x 1,000
4 byte    unsigned          time of gps reading
4 byte    unsigned          time of message generated

The total size is 22 byte, after 2 layers of encryption, the final data package
is 132 byte long for a vessel during test. When upload every 10 minutes, the
bandwidth used is 19Kbyte a day, exclude the HTTP overhead.


Requirement
===========

Fleet Monitor is written and tested on Python 2.7, there isn't much advanced
python technique involved so it is possible to run on lower version of Python.

It does require PyCrypto > 2.3 in order to import Public / Private key in ascii
format. Fortuanately, Google AppEngine already support it.

Google App Engine SDK is required to upload the software to AppEngine.

Installation
============

There are three parts.

1) the vessel:
--------------

The vessel should has a computer with gpsd installed and work properly.
PyCrypto > 2.3 should be installed. Run the rsa_keygen.py to generate a pair of
public/private rsa key. Save the private key under the same directory of
reporter.py, the public key should go to gapp directory which will upload to
Google AppEngine.

2) on the Google AppEngine:
---------------------------

Run rsa_keygen.py again to generate another key pair for the part runs on
AppEngine. The public key should be distributed to every peers, including the
vessel and the end user.

run
path_to_app_engine_sdk/appcfg update path_to_localpart
upload it to App Engine.

Please refer to App Engine's Document for detail.

3) on the end user's machine:
-----------------------------

Download and install python and pycryto. Run rsa_keygen.py, save the public key
to gapp directory.

Configure
=========

All config options are in peers.conf, hope that file is self-explantory.



If you have any comments, corrections, or improvements, please post to gpsd's
mailing list, or contact Chen Wei<weichen302@gmx.com>.
