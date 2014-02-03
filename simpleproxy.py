#!/usr/bin/env python
# coding:utf-8
# Based on GoAgent 3.1.5 by Phus Lu <phus.lu@gmail.com>
# Author: Wang Wei Qiang <wwqgtxx@gmail.com>

__version__ = '2.0.0'

import sys
import os
import glob

sys.path += glob.glob('%s/*.egg' % os.path.dirname(os.path.abspath(__file__)))
sys.path += glob.glob('%s/lib/*.egg' % os.path.dirname(os.path.abspath(__file__)))

sys.dont_write_bytecode = True

try:
    import gevent
    import gevent.socket
    import gevent.server
    import gevent.queue
    import gevent.monkey
    gevent.monkey.patch_all(subprocess=True)
except ImportError:
    gevent = None
except TypeError:
    gevent.monkey.patch_all()
    sys.stderr.write('\033[31m  Warning: Please update gevent to the latest 1.0 version!\033[0m\n')

import errno
import binascii
import time
import struct
import collections
import zlib
import functools
import itertools
import re
import io
import fnmatch
import traceback
import random
import base64
import string
import hashlib
import threading
import thread
import socket
import ssl
import select
import Queue
import SocketServer
import ConfigParser
import BaseHTTPServer
import httplib
import urllib2
import urlparse
try:
    import OpenSSL
except ImportError:
    OpenSSL = None


NetWorkIOError = (socket.error, ssl.SSLError, OSError) if not OpenSSL else (socket.error, ssl.SSLError, OpenSSL.SSL.Error, OSError)


class Logging(type(sys)):
    CRITICAL = 50
    FATAL = CRITICAL
    ERROR = 40
    WARNING = 30
    WARN = WARNING
    INFO = 20
    DEBUG = 10
    NOTSET = 0

    def __init__(self, *args, **kwargs):
        self.level = self.__class__.INFO
        self.__set_error_color = lambda: None
        self.__set_warning_color = lambda: None
        self.__set_debug_color = lambda: None
        self.__reset_color = lambda: None
        if hasattr(sys.stderr, 'isatty') and sys.stderr.isatty():
            if os.name == 'nt':
                import ctypes
                SetConsoleTextAttribute = ctypes.windll.kernel32.SetConsoleTextAttribute
                GetStdHandle = ctypes.windll.kernel32.GetStdHandle
                self.__set_error_color = lambda: SetConsoleTextAttribute(GetStdHandle(-11), 0x04)
                self.__set_warning_color = lambda: SetConsoleTextAttribute(GetStdHandle(-11), 0x06)
                self.__set_debug_color = lambda: SetConsoleTextAttribute(GetStdHandle(-11), 0x002)
                self.__reset_color = lambda: SetConsoleTextAttribute(GetStdHandle(-11), 0x07)
            elif os.name == 'posix':
                self.__set_error_color = lambda: sys.stderr.write('\033[31m')
                self.__set_warning_color = lambda: sys.stderr.write('\033[33m')
                self.__set_debug_color = lambda: sys.stderr.write('\033[32m')
                self.__reset_color = lambda: sys.stderr.write('\033[0m')

    @classmethod
    def getLogger(cls, *args, **kwargs):
        return cls(*args, **kwargs)

    def basicConfig(self, *args, **kwargs):
        self.level = int(kwargs.get('level', self.__class__.INFO))
        if self.level > self.__class__.DEBUG:
            self.debug = self.dummy
        if self.level > self.__class__.INFO:
            self.info = self.dummy

    def log(self, level, fmt, *args, **kwargs):
        sys.stderr.write('%s - [%s] %s\n' % (level, time.ctime()[4:-5], fmt % args))

    def dummy(self, *args, **kwargs):
        pass

    def debug(self, fmt, *args, **kwargs):
        self.__set_debug_color()
        self.log('DEBUG', fmt, *args, **kwargs)
        self.__reset_color()

    def info(self, fmt, *args, **kwargs):
        self.log('INFO', fmt, *args)

    def warning(self, fmt, *args, **kwargs):
        self.__set_warning_color()
        self.log('WARNING', fmt, *args, **kwargs)
        self.__reset_color()

    def warn(self, fmt, *args, **kwargs):
        self.warning(fmt, *args, **kwargs)

    def error(self, fmt, *args, **kwargs):
        self.__set_error_color()
        self.log('ERROR', fmt, *args, **kwargs)
        self.__reset_color()

    def exception(self, fmt, *args, **kwargs):
        self.error(fmt, *args, **kwargs)
        sys.stderr.write(traceback.format_exc() + '\n')

    def critical(self, fmt, *args, **kwargs):
        self.__set_error_color()
        self.log('CRITICAL', fmt, *args, **kwargs)
        self.__reset_color()
logging = sys.modules['logging'] = Logging('logging')


class CertUtil(object):
    """CertUtil module, based on mitmproxy"""

    ca_vendor = 'GoAgent'
    ca_certdir = 'certs'
    ca_lock = threading.Lock()

    @staticmethod
    def create_ca():
        key = OpenSSL.crypto.PKey()
        key.generate_key(OpenSSL.crypto.TYPE_RSA, 2048)
        ca = OpenSSL.crypto.X509()
        ca.set_serial_number(0)
        ca.set_version(2)
        subj = ca.get_subject()
        subj.countryName = 'CN'
        subj.stateOrProvinceName = 'Internet'
        subj.localityName = 'Cernet'
        subj.organizationName = CertUtil.ca_vendor
        subj.organizationalUnitName = '%s Root' % CertUtil.ca_vendor
        subj.commonName = '%s CA' % CertUtil.ca_vendor
        ca.gmtime_adj_notBefore(0)
        ca.gmtime_adj_notAfter(24 * 60 * 60 * 3652)
        ca.set_issuer(ca.get_subject())
        ca.set_pubkey(key)
        ca.add_extensions([
            OpenSSL.crypto.X509Extension(b'basicConstraints', True, b'CA:TRUE'),
            OpenSSL.crypto.X509Extension(b'nsCertType', True, b'sslCA'),
            OpenSSL.crypto.X509Extension(b'extendedKeyUsage', True, b'serverAuth,clientAuth,emailProtection,timeStamping,msCodeInd,msCodeCom,msCTLSign,msSGC,msEFS,nsSGC'),
            OpenSSL.crypto.X509Extension(b'keyUsage', False, b'keyCertSign, cRLSign'),
            OpenSSL.crypto.X509Extension(b'subjectKeyIdentifier', False, b'hash', subject=ca), ])
        ca.sign(key, 'sha1')
        return key, ca

    @staticmethod
    def dump_ca():
        key, ca = CertUtil.create_ca()
        with open(CertUtil.ca_keyfile, 'wb') as fp:
            fp.write(OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, ca))
            fp.write(OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, key))

    @staticmethod
    def _get_cert(commonname, sans=()):
        with open(CertUtil.ca_keyfile, 'rb') as fp:
            content = """
-----BEGIN CERTIFICATE-----
MIIDUjCCAjoCAQAwDQYJKoZIhvcNAQEFBQAwbzEVMBMGA1UECxMMR29BZ2VudCBS
b290MRAwDgYDVQQKEwdHb0FnZW50MRMwEQYDVQQDEwpHb0FnZW50IENBMREwDwYD
VQQIEwhJbnRlcm5ldDELMAkGA1UEBhMCQ04xDzANBgNVBAcTBkNlcm5ldDAeFw0x
MTA0MjAxNzM3MzVaFw0zMTA0MjAxNzM3MzVaMG8xFTATBgNVBAsTDEdvQWdlbnQg
Um9vdDEQMA4GA1UEChMHR29BZ2VudDETMBEGA1UEAxMKR29BZ2VudCBDQTERMA8G
A1UECBMISW50ZXJuZXQxCzAJBgNVBAYTAkNOMQ8wDQYDVQQHEwZDZXJuZXQwggEi
MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC0jV3yx3yGAHlQqzm4fbVascvT
nyCdtParWBnQn5A3U9pJjI47SCo8j7FfeoYSL0mHbJ0mjafTnw+/ewb09AQIkdEl
n6smojl7NOKs1Yhh0yldB6kQWiBPr/XKMBskmvcyjJEqkU6hwtibASaAZt+q5clT
BJ2XRaeAaMDeDbYDchFa7MTNhoQMdQFu1UhqkJxtuVMBEs1/qPbx5O9pqy1RgAeK
WvxyCzVRi2hHaTns+weZBJ6N71afyvr1etGqqtWVpjpobk1ZFBYk4xpznCbm4iqP
Ar9nqdGDw1IJIdX0DyMJIJrpwOf94pAK9v6zG0jnsbMqromL18kEMXZgYSMlAgMB
AAEwDQYJKoZIhvcNAQEFBQADggEBAASiRZFCcgQ8VsncB8wKG+bmN9UZhXLJYRGp
m3KIUy/zG6mMWG/3TgkPn8ivNAkrk+1ul5SrRvot/Q7XWpb0/yKX0faX/512JF2G
220gopqo4amj+g7SBKxzW8VhLQF6dm99eUd27JbAzi5VKXR0dMFECk2rFlA5gAR5
zzFijaXHuObMtd2S292wji79JWocA0z6WVM5Qokw4hRTsXWfXL0BJTL3i/xRrEzW
sdecYFpNhaEKldjegazoqAqiAMJj7PDU1AqdprNsq+3/tAmCvn0URkas4QhkvtqS
FO6OGm/PZe5GbkBpAKdfLYFfEMO17SAGHHqAsIKAFfuHYONRGSM=
-----END CERTIFICATE-----
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAtI1d8sd8hgB5UKs5uH21WrHL058gnbT2q1gZ0J+QN1PaSYyO
O0gqPI+xX3qGEi9Jh2ydJo2n058Pv3sG9PQECJHRJZ+rJqI5ezTirNWIYdMpXQep
EFogT6/1yjAbJJr3MoyRKpFOocLYmwEmgGbfquXJUwSdl0WngGjA3g22A3IRWuzE
zYaEDHUBbtVIapCcbblTARLNf6j28eTvaastUYAHilr8cgs1UYtoR2k57PsHmQSe
je9Wn8r69XrRqqrVlaY6aG5NWRQWJOMac5wm5uIqjwK/Z6nRg8NSCSHV9A8jCSCa
6cDn/eKQCvb+sxtI57GzKq6Ji9fJBDF2YGEjJQIDAQABAoIBACB3n2JN/xV1tlsM
P1fuuxLxD+8hGVNivEy5jgLW/q8EVCePr+/3HSlAyauas8tHV5iTrnrFVF2Yp9NO
A0U/MA5+cjaqzLMozt9Z9j0QNPMqbrC89Ojs3AyYXsGZ/veJKlSbtGsMMDCkgiD1
hv/l/+iSY66bEN+n9eQAclY77vQVXLSoCMReVfbdUxU9Q1MywODGf5Kng84gTyT/
zd+xEfFHz8zbCDyw3Hd3hGJ2FxN+yFz1uI29ORb3/R7N9dZgsWf2fsfiRVPGuhAH
RNlDockImB+BKeidx14sMim5p7s8heVYkBVW3SIOEReqz59b8x4QVhhZrzYWSHNq
Gi0pLiECgYEA26v6b+rsxT//PznJSEhLyrg1Jo6XeWmFlwZY0KoipH6sxX/YPrDZ
bOPN8KvAHtRltRLFs3L2iRaO2jltjxHGVF4FSYrf5KSExuj6/ABHxWM0YtezfDwR
hU1ORg5QwVegMoOgsphS8ts2xn6T6wIwpBgtFPY84A52IBVn5CHuQtkCgYEA0mk5
EpnZfmMT5ldcZ7JlZrxfWKvDHIcuA0neIBsd4oIcEfRhDC3TolH6pB4z4SCqyYw3
t5HMiTx8yz074mycTcOcXO1Cs49kMZwbzKziRXpUdCW4EIo0DG+6LqwetPgYzozg
FeTiGQBHqjrzjBLZ3RfozICbo7dvYHkVLK92my0CgYBWNBjlDnW3ujN6Jj0cxnIn
rT3+UXqTxJsN9wmnaPyLPMKkBlVf1JqeJo9MYLnV31fCRQmcMAMbLOUGMf8SY9FG
jlbY00ylNwJ75DWJ6ro/dXy7RRZELHZbr0iGKVv7Y12UNR88tpXmg6vtHQMC+CsK
Wgpm7XJaIpKsaHoKhl4vkQKBgBBBTsZwGkxYTSZDY4EjWBAax2brRhSDIPviDgX+
8k0YbiC493Jga/QjTzC0oJ9ozajqazeETP/hK2bsIR858s1TKlZHghqrHjty6vbh
+E0TyUh7zX+BncnEK+cFJw4mCIyUd49ZcloqGl89VKlin3AkM7jwypVYS4Nxd0BP
geM1AoGBALOWNmYm9d4gRhUv14oJRiA+e+4evswiWvVdnS6UJ4tst0NlEKWahtpR
kdAjav8WV1n6IbkJC2L743Ozjb63z5w6p5O7OtTyYUWbLt1hvNkHlkNP8AjRQP8E
+N2jjrMAdbEwahPNAX9QlzHpF62AfEGQ3oODUm06TGTq+yAPSyYm
-----END RSA PRIVATE KEY-----

"""
            key = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, content)
            ca = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, content)

        pkey = OpenSSL.crypto.PKey()
        pkey.generate_key(OpenSSL.crypto.TYPE_RSA, 2048)

        req = OpenSSL.crypto.X509Req()
        subj = req.get_subject()
        subj.countryName = 'CN'
        subj.stateOrProvinceName = 'Internet'
        subj.localityName = 'Cernet'
        subj.organizationalUnitName = '%s Branch' % CertUtil.ca_vendor
        if commonname[0] == '.':
            subj.commonName = '*' + commonname
            subj.organizationName = '*' + commonname
            sans = ['*'+commonname] + [x for x in sans if x != '*'+commonname]
        else:
            subj.commonName = commonname
            subj.organizationName = commonname
            sans = [commonname] + [x for x in sans if x != commonname]
        #req.add_extensions([OpenSSL.crypto.X509Extension(b'subjectAltName', True, ', '.join('DNS: %s' % x for x in sans)).encode()])
        req.set_pubkey(pkey)
        req.sign(pkey, 'sha1')

        cert = OpenSSL.crypto.X509()
        cert.set_version(2)
        try:
            cert.set_serial_number(int(hashlib.md5(commonname.encode('utf-8')).hexdigest(), 16))
        except OpenSSL.SSL.Error:
            cert.set_serial_number(int(time.time()*1000))
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(60 * 60 * 24 * 3652)
        cert.set_issuer(ca.get_subject())
        cert.set_subject(req.get_subject())
        cert.set_pubkey(req.get_pubkey())
        if commonname[0] == '.':
            sans = ['*'+commonname] + [s for s in sans if s != '*'+commonname]
        else:
            sans = [commonname] + [s for s in sans if s != commonname]
        #cert.add_extensions([OpenSSL.crypto.X509Extension(b'subjectAltName', True, ', '.join('DNS: %s' % x for x in sans))])
        cert.sign(key, 'sha1')

        certfile = os.path.join(CertUtil.ca_certdir, commonname + '.crt')
        with open(certfile, 'wb') as fp:
            fp.write(OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, cert))
            fp.write(OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, pkey))
        return certfile

    @staticmethod
    def get_cert(commonname, sans=()):
        if commonname.count('.') >= 2 and len(commonname.split('.')[-2]) > 4:
            commonname = '.'+commonname.partition('.')[-1]
        certfile = os.path.join(CertUtil.ca_certdir, commonname + '.crt')
        if os.path.exists(certfile):
            return certfile
        elif OpenSSL is None:
            return CertUtil.ca_keyfile
        else:
            with CertUtil.ca_lock:
                if os.path.exists(certfile):
                    return certfile
                return CertUtil._get_cert(commonname, sans)

    @staticmethod
    def import_ca(certfile):
        commonname = os.path.splitext(os.path.basename(certfile))[0]
        if OpenSSL:
            try:
                with open(certfile, 'rb') as fp:
                    x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, fp.read())
                    commonname = next(v.decode() for k, v in x509.get_subject().get_components() if k == b'O')
            except Exception as e:
                logging.error('load_certificate(certfile=%r) failed:%s', certfile, e)
        if sys.platform.startswith('win'):
            import ctypes
            with open(certfile, 'rb') as fp:
                certdata = fp.read()
                if certdata.startswith(b'-----'):
                    begin = b'-----BEGIN CERTIFICATE-----'
                    end = b'-----END CERTIFICATE-----'
                    certdata = base64.b64decode(b''.join(certdata[certdata.find(begin)+len(begin):certdata.find(end)].strip().splitlines()))
                crypt32 = ctypes.WinDLL(b'crypt32.dll'.decode())
                store_handle = crypt32.CertOpenStore(10, 0, 0, 0x4000 | 0x20000, b'ROOT'.decode())
                if not store_handle:
                    return -1
                if crypt32.CertFindCertificateInStore(store_handle, 0x1, 0, 0x80007, CertUtil.ca_vendor.decode(), None):
                    return 0
                ret = crypt32.CertAddEncodedCertificateToStore(store_handle, 0x1, certdata, len(certdata), 4, None)
                crypt32.CertCloseStore(store_handle, 0)
                del crypt32
                return 0 if ret else -1
        elif sys.platform == 'darwin':
            return os.system(('security find-certificate -a -c "%s" | grep "%s" >/dev/null || security add-trusted-cert -d -r trustRoot -k "/Library/Keychains/System.keychain" "%s"' % (commonname, commonname, certfile.decode('utf-8'))).encode('utf-8'))
        elif sys.platform.startswith('linux'):
            import platform
            platform_distname = platform.dist()[0]
            if platform_distname == 'Ubuntu':
                pemfile = "/etc/ssl/certs/%s.pem" % commonname
                new_certfile = "/usr/local/share/ca-certificates/%s.crt" % commonname
                if not os.path.exists(pemfile):
                    return os.system('cp "%s" "%s" && update-ca-certificates' % (certfile, new_certfile))
            elif any(os.path.isfile('%s/certutil' % x) for x in os.environ['PATH'].split(os.pathsep)):
                return os.system('certutil -L -d sql:$HOME/.pki/nssdb | grep "%s" || certutil -d sql:$HOME/.pki/nssdb -A -t "C,," -n "%s" -i "%s"' % (commonname, commonname, certfile))
            else:
                logging.warning('please install *libnss3-tools* package to import GoAgent root ca')
        return 0

    @staticmethod
    def check_ca():
        #Check CA exists
        capath = os.path.join(os.path.dirname(os.path.abspath(__file__)), CertUtil.ca_keyfile)
        certdir = os.path.join(os.path.dirname(os.path.abspath(__file__)), CertUtil.ca_certdir)
        if not os.path.exists(capath):
            if not OpenSSL:
                logging.critical('CA.key is not exist and OpenSSL is disabled, ABORT!')
                sys.exit(-1)
            if os.path.exists(certdir):
                if os.path.isdir(certdir):
                    any(os.remove(x) for x in glob.glob(certdir+'/*.crt')+glob.glob(certdir+'/.*.crt'))
                else:
                    os.remove(certdir)
                    os.mkdir(certdir)
            CertUtil.dump_ca()
        if glob.glob('%s/*.key' % CertUtil.ca_certdir):
            for filename in glob.glob('%s/*.key' % CertUtil.ca_certdir):
                try:
                    os.remove(filename)
                    os.remove(os.path.splitext(filename)[0]+'.crt')
                except EnvironmentError:
                    pass
        #Check CA imported
        if CertUtil.import_ca(capath) != 0:
            logging.warning('install root certificate failed, Please run as administrator/root/sudo')
        #Check Certs Dir
        if not os.path.exists(certdir):
            os.makedirs(certdir)


class SSLConnection(object):

    has_gevent = socket.socket is getattr(sys.modules.get('gevent.socket'), 'socket', None)

    def __init__(self, context, sock):
        self._context = context
        self._sock = sock
        self._connection = OpenSSL.SSL.Connection(context, sock)
        self._makefile_refs = 0
        if self.has_gevent:
            self._wait_read = gevent.socket.wait_read
            self._wait_write = gevent.socket.wait_write
            self._wait_readwrite = gevent.socket.wait_readwrite
        else:
            self._wait_read = lambda fd,t: select.select([fd], [], [fd], t)
            self._wait_write = lambda fd,t: select.select([], [fd], [fd], t)
            self._wait_readwrite = lambda fd,t: select.select([fd], [fd], [fd], t)

    def __getattr__(self, attr):
        if attr not in ('_context', '_sock', '_connection', '_makefile_refs'):
            return getattr(self._connection, attr)

    def accept(self):
        sock, addr = self._sock.accept()
        client = OpenSSL.SSL.Connection(sock._context, sock)
        return client, addr

    def do_handshake(self):
        timeout = self._sock.gettimeout()
        while True:
            try:
                self._connection.do_handshake()
                break
            except (OpenSSL.SSL.WantReadError, OpenSSL.SSL.WantX509LookupError, OpenSSL.SSL.WantWriteError):
                sys.exc_clear()
                self._wait_readwrite(self._sock.fileno(), timeout)

    def connect(self, *args, **kwargs):
        timeout = self._sock.gettimeout()
        while True:
            try:
                self._connection.connect(*args, **kwargs)
                break
            except (OpenSSL.SSL.WantReadError, OpenSSL.SSL.WantX509LookupError):
                sys.exc_clear()
                self._wait_read(self._sock.fileno(), timeout)
            except OpenSSL.SSL.WantWriteError:
                sys.exc_clear()
                self._wait_write(self._sock.fileno(), timeout)

    def send(self, data, flags=0):
        timeout = self._sock.gettimeout()
        while True:
            try:
                self._connection.send(data, flags)
                break
            except (OpenSSL.SSL.WantReadError, OpenSSL.SSL.WantX509LookupError):
                sys.exc_clear()
                self._wait_read(self._sock.fileno(), timeout)
            except OpenSSL.SSL.WantWriteError:
                sys.exc_clear()
                self._wait_write(self._sock.fileno(), timeout)
            except OpenSSL.SSL.SysCallError as e:
                if e[0] == -1 and not data:
                    # errors when writing empty strings are expected and can be ignored
                    return 0
                raise

    def recv(self, bufsiz, flags=0):
        timeout = self._sock.gettimeout()
        pending = self._connection.pending()
        if pending:
            return self._connection.recv(min(pending, bufsiz))
        while True:
            try:
                return self._connection.recv(bufsiz, flags)
            except (OpenSSL.SSL.WantReadError, OpenSSL.SSL.WantX509LookupError):
                sys.exc_clear()
                self._wait_read(self._sock.fileno(), timeout)
            except OpenSSL.SSL.WantWriteError:
                sys.exc_clear()
                self._wait_write(self._sock.fileno(), timeout)
            except OpenSSL.SSL.ZeroReturnError:
                return ''

    def read(self, bufsiz, flags=0):
        return self.recv(bufsiz, flags)

    def write(self, buf, flags=0):
        return self.sendall(buf, flags)

    def close(self):
        if self._makefile_refs < 1:
            self._connection = None
            if self._sock:
                socket.socket.close(self._sock)
        else:
            self._makefile_refs -= 1

    def makefile(self, mode='r', bufsize=-1):
        self._makefile_refs += 1
        return socket._fileobject(self, mode, bufsize, close=True)



class ProxyUtil(object):
    """ProxyUtil module, based on urllib2"""

    @staticmethod
    def parse_proxy(proxy):
        return urllib2._parse_proxy(proxy)

    @staticmethod
    def get_system_proxy():
        proxies = urllib2.getproxies()
        return proxies.get('https') or proxies.get('http') or {}

    @staticmethod
    def get_listen_ip():
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(('8.8.8.8', 53))
        listen_ip = sock.getsockname()[0]
        sock.close()
        return listen_ip



class DNSUtil(object):
    """
    http://gfwrev.blogspot.com/2009/11/gfwdns.html
    http://zh.wikipedia.org/wiki/域名服务器缓存污染
    http://support.microsoft.com/kb/241352
    """
    blacklist = set(['1.1.1.1',
                     '255.255.255.255',
                     # for google+
                     '74.125.127.102',
                     '74.125.155.102',
                     '74.125.39.102',
                     '74.125.39.113',
                     '209.85.229.138',
                     # other ip list
                     '4.36.66.178',
                     '8.7.198.45',
                     '37.61.54.158',
                     '46.82.174.68',
                     '59.24.3.173',
                     '64.33.88.161',
                     '64.33.99.47',
                     '64.66.163.251',
                     '65.104.202.252',
                     '65.160.219.113',
                     '66.45.252.237',
                     '72.14.205.104',
                     '72.14.205.99',
                     '78.16.49.15',
                     '93.46.8.89',
                     '128.121.126.139',
                     '159.106.121.75',
                     '169.132.13.103',
                     '192.67.198.6',
                     '202.106.1.2',
                     '202.181.7.85',
                     '203.161.230.171',
                     '203.98.7.65',
                     '207.12.88.98',
                     '208.56.31.43',
                     '209.145.54.50',
                     '209.220.30.174',
                     '209.36.73.33',
                     '209.85.229.138',
                     '211.94.66.147',
                     '213.169.251.35',
                     '216.221.188.182',
                     '216.234.179.13',
                     '243.185.187.3',
                     '243.185.187.39'])
    cndnsserver = ['114.114.114.114','114.114.115.115','114.114.114.119','114.114.115.119','114.114.114.110','114.114.115.110']
    max_retry = 3
    max_wait = 3

    @staticmethod
    def _reply_to_iplist(data):
        assert isinstance(data, bytes)
        if bytes is str:
            iplist = ['.'.join(str(ord(x)) for x in s) for s in re.findall('\xc0.\x00\x01\x00\x01.{6}(.{4})', data) if all(ord(x) <= 255 for x in s)]
        else:
            iplist = ['.'.join(str(x) for x in s) for s in re.findall(b'\xc0.\x00\x01\x00\x01.{6}(.{4})', data) if all(x <= 255 for x in s)]
        return iplist

    @staticmethod
    def is_bad_reply(data):
        assert isinstance(data, bytes)
        if bytes is str:
            iplist = ['.'.join(str(ord(x)) for x in s) for s in re.findall(b'\xc0.\x00\x01\x00\x01.{6}(.{4})', data)+re.findall(b'\x00\x01\x00\x01.{6}(.{4})', data) if all(ord(x) <= 255 for x in s)]
        else:
            iplist = ['.'.join(str(x) for x in s) for s in re.findall(b'\xc0.\x00\x01\x00\x01.{6}(.{4})', data)+re.findall(b'\x00\x01\x00\x01.{6}(.{4})', data) if all(x <= 255 for x in s)]
        return any(x in DNSUtil.blacklist for x in iplist)

    @staticmethod
    def _remote_resolve(dnsserver, qname, timeout=None):
        if isinstance(dnsserver, tuple):
            dnsserver, port = dnsserver
        else:
            port = 53
        for i in range(DNSUtil.max_retry):
            data = os.urandom(2)
            data += b'\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'
            data += ''.join(chr(len(x))+x for x in qname.split('.')).encode()
            data += b'\x00\x00\x01\x00\x01'
            address_family = socket.AF_INET6 if ':' in dnsserver else socket.AF_INET
            sock = None
            try:
                if i < DNSUtil.max_retry-1 and dnsserver in DNSUtil.cndnsserver:
                    # UDP mode query
                    sock = socket.socket(family=address_family, type=socket.SOCK_DGRAM)
                    sock.settimeout(timeout)
                    sock.sendto(data, (dnsserver, port))
                    for i in range(DNSUtil.max_wait):
                        data = sock.recv(512)
                        if data and not DNSUtil.is_bad_reply(data):
                            return data[2:]
                        else:
                            if qname.endswith('.google.com'):
                                logging.warning('DNSUtil._remote_resolve(dnsserver=%r, %r) return poisoned udp data=%r', qname, dnsserver, data)
                elif dnsserver not in DNSUtil.cndnsserver:
                    # TCP mode query
                    sock = socket.socket(family=address_family, type=socket.SOCK_STREAM)
                    sock.settimeout(timeout)
                    sock.connect((dnsserver, port))
                    data = struct.pack('>h', len(data)) + data
                    sock.send(data)
                    rfile = sock.makefile('rb', 512)
                    data = rfile.read(2)
                    if not data:
                        logging.warning('DNSUtil._remote_resolve(dnsserver=%r, %r) return bad tcp header data=%r', qname, dnsserver, data)
                        continue
                    data = rfile.read(struct.unpack('>h', data)[0])
                    if data and not DNSUtil.is_bad_reply(data):
                        return data[2:]
                    else:
                        logging.warning('DNSUtil._remote_resolve(dnsserver=%r, %r) return bad tcp data=%r', qname, dnsserver, data)
                else:
                    break
            except (socket.error, ssl.SSLError, OSError) as e:
                if e.args[0] in (errno.ETIMEDOUT, 'timed out'):
                    continue
            except Exception as e:
                raise
            finally:
                if sock:
                    sock.close()

    @staticmethod
    def remote_resolve(dnsserver, qname, timeout=None):
        data = DNSUtil._remote_resolve(dnsserver, qname, timeout)
        iplist = DNSUtil._reply_to_iplist(data or b'')
        return iplist


def spawn_later(seconds, target, *args, **kwargs):
    def wrap(*args, **kwargs):
        __import__('time').sleep(seconds)
        return target(*args, **kwargs)
    return __import__('thread').start_new_thread(wrap, args, kwargs)


class HTTPUtil(object):
    """HTTP Request Class"""

    MessageClass = dict
    protocol_version = 'HTTP/1.1'
    skip_headers = frozenset(['Vary', 'Via', 'X-Forwarded-For', 'Proxy-Authorization', 'Proxy-Connection', 'Upgrade', 'X-Chrome-Variations', 'Connection', 'Cache-Control'])
    ssl_validate = False
    ssl_obfuscate = False
    ssl_ciphers = ':'.join(['ECDHE-ECDSA-AES256-SHA',
                            'ECDHE-RSA-AES256-SHA',
                            'DHE-RSA-CAMELLIA256-SHA',
                            'DHE-DSS-CAMELLIA256-SHA',
                            'DHE-RSA-AES256-SHA',
                            'DHE-DSS-AES256-SHA',
                            'ECDH-RSA-AES256-SHA',
                            'ECDH-ECDSA-AES256-SHA',
                            'CAMELLIA256-SHA',
                            'AES256-SHA',
                            'ECDHE-ECDSA-RC4-SHA',
                            'ECDHE-ECDSA-AES128-SHA',
                            'ECDHE-RSA-RC4-SHA',
                            'ECDHE-RSA-AES128-SHA',
                            'DHE-RSA-CAMELLIA128-SHA',
                            'DHE-DSS-CAMELLIA128-SHA',
                            'DHE-RSA-AES128-SHA',
                            'DHE-DSS-AES128-SHA',
                            'ECDH-RSA-RC4-SHA',
                            'ECDH-RSA-AES128-SHA',
                            'ECDH-ECDSA-RC4-SHA',
                            'ECDH-ECDSA-AES128-SHA',
                            'SEED-SHA',
                            'CAMELLIA128-SHA',
                            'RC4-SHA',
                            'RC4-MD5',
                            'AES128-SHA',
                            'ECDHE-ECDSA-DES-CBC3-SHA',
                            'ECDHE-RSA-DES-CBC3-SHA',
                            'EDH-RSA-DES-CBC3-SHA',
                            'EDH-DSS-DES-CBC3-SHA',
                            'ECDH-RSA-DES-CBC3-SHA',
                            'ECDH-ECDSA-DES-CBC3-SHA',
                            'DES-CBC3-SHA',
                            'TLS_EMPTY_RENEGOTIATION_INFO_SCSV'])

    def __init__(self, max_window=4, max_timeout=8, max_retry=4):
        # http://docs.python.org/dev/library/ssl.html
        # http://blog.ivanristic.com/2009/07/examples-of-the-information-collected-from-ssl-handshakes.html
        # http://src.chromium.org/svn/trunk/src/net/third_party/nss/ssl/sslenum.c
        # http://www.openssl.org/docs/apps/ciphers.html
        # openssl s_server -accept 443 -key CA.crt -cert CA.crt
        # set_ciphers as Modern Browsers
        self.max_window = max_window
        self.max_retry = max_retry
        self.max_timeout = max_timeout
        self.tcp_connection_time = collections.defaultdict(float)
        self.tcp_connection_cache = collections.defaultdict(Queue.PriorityQueue)
        self.ssl_connection_time = collections.defaultdict(float)
        self.ssl_connection_cache = collections.defaultdict(Queue.PriorityQueue)
        self.dns = {}
        self.openssl_context = None

    def set_openssl_option(self, validate=True, obfuscate=True):
        if self.openssl_context is None:
            self.openssl_context = OpenSSL.SSL.Context(OpenSSL.SSL.TLSv1_METHOD)
            self.openssl_context.set_session_id(binascii.b2a_hex(os.urandom(10)))
            if hasattr(OpenSSL.SSL, 'SESS_CACHE_BOTH'):
                self.openssl_context.set_session_cache_mode(OpenSSL.SSL.SESS_CACHE_BOTH)
        if validate:
            self.openssl_context.load_verify_locations(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'cacert.pem'))
            self.openssl_context.set_verify(OpenSSL.SSL.VERIFY_PEER, lambda c, x, e, d, ok: ok)
        if obfuscate:
            ssl_ciphers = ':'.join(x for x in self.ssl_ciphers.split(':') if random.random() > 0.5)
            self.openssl_context.set_cipher_list(ssl_ciphers)

    def dns_resolve(self, host, dnsserver='', ipv4_only=True):
        iplist = self.dns.get(host)
        if not iplist:
            if not dnsserver:
                iplist = list(set(socket.gethostbyname_ex(host)[-1]) - DNSUtil.blacklist)
            else:
                iplist = DNSUtil.remote_resolve(dnsserver, host, timeout=2)
            if not iplist:
                iplist = DNSUtil.remote_resolve('8.8.4.4', host, timeout=2)
            if ipv4_only:
                iplist = [ip for ip in iplist if re.match(r'\d+\.\d+\.\d+\.\d+', ip)]
            self.dns[host] = iplist = list(set(iplist))
        return iplist

    def create_connection(self, address, timeout=None, source_address=None, **kwargs):
        connection_cache_key = kwargs.get('cache_key')
        def _create_connection(ipaddr, timeout, queobj):
            sock = None
            try:
                # create a ipv4/ipv6 socket object
                sock = socket.socket(socket.AF_INET if ':' not in ipaddr[0] else socket.AF_INET6)
                # set reuseaddr option to avoid 10048 socket error
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                # resize socket recv buffer 8K->32K to improve browser releated application performance
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 32*1024)
                # disable negal algorithm to send http request quickly.
                sock.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, True)
                # set a short timeout to trigger timeout retry more quickly.
                sock.settimeout(timeout or self.max_timeout)
                # start connection time record
                start_time = time.time()
                # TCP connect
                sock.connect(ipaddr)
                # record TCP connection time
                self.tcp_connection_time[ipaddr] = time.time() - start_time
                # put ssl socket object to output queobj
                queobj.put(sock)
            except (socket.error, OSError) as e:
                # any socket.error, put Excpetions to output queobj.
                queobj.put(e)
                # reset a large and random timeout to the ipaddr
                self.tcp_connection_time[ipaddr] = self.max_timeout+random.random()
                # close tcp socket
                if sock:
                    sock.close()
        def _close_connection(count, queobj):
            for i in range(count):
                sock = queobj.get()
                if sock and not isinstance(sock, Exception):
                    if connection_cache_key and i == 0:
                        self.tcp_connection_cache[connection_cache_key].put((time.time(), sock))
                    else:
                        sock.close()
        try:
            while connection_cache_key:
                ctime, sock = self.tcp_connection_cache[connection_cache_key].get_nowait()
                if time.time() - ctime < 30:
                    return sock
        except Queue.Empty:
            pass
        host, port = address
        result = None
        addresses = [(x, port) for x in self.dns_resolve(host)]
        if port == 443:
            get_connection_time = lambda addr: self.ssl_connection_time.__getitem__(addr) or self.tcp_connection_time.__getitem__(addr)
        else:
            get_connection_time = self.tcp_connection_time.__getitem__
        for i in range(self.max_retry):
            window = min((self.max_window+1)//2 + i, len(addresses))
            addresses.sort(key=get_connection_time)
            addrs = addresses[:window] + random.sample(addresses, min(len(addresses), window, self.max_window-window))
            queobj = Queue.Queue()
            for addr in addrs:
                thread.start_new_thread(_create_connection, (addr, timeout, queobj))
            for i in range(len(addrs)):
                result = queobj.get()
                if not isinstance(result, (socket.error, OSError)):
                    thread.start_new_thread(_close_connection, (len(addrs)-i-1, queobj))
                    return result
                else:
                    if i == 0:
                        # only output first error
                        logging.warning('create_connection to %s return %r, try again.', addrs, result)

    def create_ssl_connection(self, address, timeout=None, source_address=None, **kwargs):
        connection_cache_key = kwargs.get('cache_key')
        validate = kwargs.get('validate')
        def _create_ssl_connection(ipaddr, timeout, queobj):
            sock = None
            ssl_sock = None
            try:
                # create a ipv4/ipv6 socket object
                sock = socket.socket(socket.AF_INET if ':' not in ipaddr[0] else socket.AF_INET6)
                # set reuseaddr option to avoid 10048 socket error
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                # resize socket recv buffer 8K->32K to improve browser releated application performance
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 32*1024)
                # disable negal algorithm to send http request quickly.
                sock.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, True)
                # set a short timeout to trigger timeout retry more quickly.
                sock.settimeout(timeout or self.max_timeout)
                # pick up the certificate
                if not validate:
                    ssl_sock = ssl.wrap_socket(sock, do_handshake_on_connect=False)
                else:
                    ssl_sock = ssl.wrap_socket(sock, cert_reqs=ssl.CERT_REQUIRED, ca_certs=os.path.join(os.path.dirname(os.path.abspath(__file__)),'cacert.pem'), do_handshake_on_connect=False)
                ssl_sock.settimeout(timeout or self.max_timeout)
                # start connection time record
                start_time = time.time()
                # TCP connect
                ssl_sock.connect(ipaddr)
                connected_time = time.time()
                # SSL handshake
                ssl_sock.do_handshake()
                handshaked_time = time.time()
                # record TCP connection time
                self.tcp_connection_time[ipaddr] = ssl_sock.tcp_time = connected_time - start_time
                # record SSL connection time
                self.ssl_connection_time[ipaddr] = ssl_sock.ssl_time = handshaked_time - start_time
                ssl_sock.ssl_time = connected_time - start_time
                # sometimes, we want to use raw tcp socket directly(select/epoll), so setattr it to ssl socket.
                ssl_sock.sock = sock
                # verify SSL certificate.
                if validate and address[0].endswith('.appspot.com'):
                    cert = ssl_sock.getpeercert()
                    orgname = next((v for ((k, v),) in cert['subject'] if k == 'organizationName'))
                    if not orgname.lower().startswith('google '):
                        raise ssl.SSLError("%r certificate organizationName(%r) not startswith 'Google'" % (address[0], orgname))
                # put ssl socket object to output queobj
                queobj.put(ssl_sock)
            except (socket.error, ssl.SSLError, OSError) as e:
                # any socket.error, put Excpetions to output queobj.
                queobj.put(e)
                # reset a large and random timeout to the ipaddr
                self.ssl_connection_time[ipaddr] = self.max_timeout + random.random()
                # close ssl socket
                if ssl_sock:
                    ssl_sock.close()
                # close tcp socket
                if sock:
                    sock.close()
        def _create_openssl_connection(ipaddr, timeout, queobj):
            sock = None
            ssl_sock = None
            try:
                # create a ipv4/ipv6 socket object
                sock = socket.socket(socket.AF_INET if ':' not in ipaddr[0] else socket.AF_INET6)
                # set reuseaddr option to avoid 10048 socket error
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                # resize socket recv buffer 8K->32K to improve browser releated application performance
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 32*1024)
                # disable negal algorithm to send http request quickly.
                sock.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, True)
                # set a short timeout to trigger timeout retry more quickly.
                sock.settimeout(timeout or self.max_timeout)
                # pick up the certificate
                server_hostname = b'www.google.com' if address[0].endswith('.appspot.com') else None
                ssl_sock = SSLConnection(self.openssl_context, sock)
                ssl_sock.set_connect_state()
                if server_hostname:
                    ssl_sock.set_tlsext_host_name(server_hostname)
                # start connection time record
                start_time = time.time()
                # TCP connect
                ssl_sock.connect(ipaddr)
                connected_time = time.time()
                # SSL handshake
                ssl_sock.do_handshake()
                handshaked_time = time.time()
                # record TCP connection time
                self.tcp_connection_time[ipaddr] = ssl_sock.tcp_time = connected_time - start_time
                # record SSL connection time
                self.ssl_connection_time[ipaddr] = ssl_sock.ssl_time = handshaked_time - start_time
                # sometimes, we want to use raw tcp socket directly(select/epoll), so setattr it to ssl socket.
                ssl_sock.sock = sock
                # verify SSL certificate.
                if validate and address[0].endswith('.appspot.com'):
                    cert = ssl_sock.get_peer_certificate()
                    commonname = next((v for k, v in cert.get_subject().get_components() if k == 'CN'))
                    if '.google' not in commonname and not commonname.endswith('.appspot.com'):
                        raise socket.error("Host name '%s' doesn't match certificate host '%s'" % (address[0], commonname))
                # put ssl socket object to output queobj
                queobj.put(ssl_sock)
            except (socket.error, OpenSSL.SSL.Error, OSError) as e:
                # any socket.error, put Excpetions to output queobj.
                queobj.put(e)
                # reset a large and random timeout to the ipaddr
                self.ssl_connection_time[ipaddr] = self.max_timeout + random.random()
                # close ssl socket
                if ssl_sock:
                    ssl_sock.close()
                # close tcp socket
                if sock:
                    sock.close()
        def _close_ssl_connection(count, queobj, first_tcp_time, first_ssl_time):
            for i in range(count):
                sock = queobj.get()
                ssl_time_threshold = min(1, 1.5 * first_ssl_time)
                if sock and not isinstance(sock, Exception):
                    if connection_cache_key and sock.ssl_time < ssl_time_threshold:
                        self.ssl_connection_cache[connection_cache_key].put((time.time(), sock))
                    else:
                        sock.close()
        try:
            while connection_cache_key:
                ctime, sock = self.ssl_connection_cache[connection_cache_key].get_nowait()
                if time.time() - ctime < 30:
                    return sock
        except Queue.Empty:
            pass
        host, port = address
        result = None
        # create_connection = _create_ssl_connection if not validate else _create_openssl_connection
        create_connection = _create_ssl_connection
        addresses = [(x, port) for x in self.dns_resolve(host)]
        for i in range(self.max_retry):
            window = min((self.max_window+1)//2 + i, len(addresses))
            addresses.sort(key=self.ssl_connection_time.__getitem__)
            addrs = addresses[:window] + random.sample(addresses, min(len(addresses), window, self.max_window-window))
            queobj = Queue.Queue()
            for addr in addrs:
                thread.start_new_thread(create_connection, (addr, timeout, queobj))
            for i in range(len(addrs)):
                result = queobj.get()
                if not isinstance(result, Exception):
                    thread.start_new_thread(_close_ssl_connection, (len(addrs)-i-1, queobj, result.tcp_time, result.ssl_time))
                    return result
                else:
                    if i == 0:
                        # only output first error
                        logging.warning('create_ssl_connection to %s return %r, try again.', addrs, result)


    def forward_socket(self, local, remote, timeout=60, tick=2, bufsize=8192, maxping=None, maxpong=None):
        try:
            timecount = timeout
            while 1:
                timecount -= tick
                if timecount <= 0:
                    break
                (ins, _, errors) = select.select([local, remote], [], [local, remote], tick)
                if errors:
                    break
                if ins:
                    for sock in ins:
                        data = sock.recv(bufsize)
                        if data:
                            if sock is remote:
                                local.sendall(data)
                                timecount = maxpong or timeout
                            else:
                                remote.sendall(data)
                                timecount = maxping or timeout
                        else:
                            return
        except NetWorkIOError as e:
            if e.args[0] not in (errno.ECONNABORTED, errno.ECONNRESET, errno.ENOTCONN, errno.EPIPE):
                raise
        finally:
            if local:
                local.close()
            if remote:
                remote.close()

    def _request(self, sock, method, path, protocol_version, headers, payload, bufsize=8192, crlf=None, return_sock=None):
        skip_headers = self.skip_headers
        need_crlf = bool(crlf)
        if need_crlf:
            fakehost = 'www.' + ''.join(random.choice(('bcdfghjklmnpqrstvwxyz','aeiou')[x&1]) for x in xrange(random.randint(5,20))) + random.choice(['.net', '.com', '.org'])
            request_data = 'GET / HTTP/1.1\r\nHost: %s\r\n\r\n\r\n\r\r' % fakehost
        else:
            request_data = ''
        request_data += '%s %s %s\r\n' % (method, path, protocol_version)
        request_data += ''.join('%s: %s\r\n' % (k.title(), v) for k, v in headers.items() if k.title() not in skip_headers)
        request_data += '\r\n'

        if isinstance(payload, bytes):
            sock.sendall(request_data.encode() + payload)
        elif hasattr(payload, 'read'):
            sock.sendall(request_data)
            while 1:
                data = payload.read(bufsize)
                if not data:
                    break
                sock.sendall(data)
        else:
            raise TypeError('http_util.request(payload) must be a string or buffer, not %r' % type(payload))

        if need_crlf:
            try:
                response = httplib.HTTPResponse(sock)
                response.begin()
                response.read()
            except Exception:
                logging.exception('crlf skip read')
                return None

        if return_sock:
            return sock

        response = httplib.HTTPResponse(sock, buffering=True)
        try:
            response.begin()
        except httplib.BadStatusLine:
            response = None
        return response

    def request(self, method, url, payload=None, headers={}, realhost='', bufsize=8192, crlf=None, validate=None, return_sock=None, connection_cache_key=None):
        scheme, netloc, path, _, query, _ = urlparse.urlparse(url)
        if netloc.rfind(':') <= netloc.rfind(']'):
            # no port number
            host = netloc
            port = 443 if scheme == 'https' else 80
        else:
            host, _, port = netloc.rpartition(':')
            port = int(port)
        if query:
            path += '?' + query

        if 'Host' not in headers:
            headers['Host'] = host
        if payload and 'Content-Length' not in headers:
            headers['Content-Length'] = str(len(payload))

        for i in range(self.max_retry):
            sock = None
            ssl_sock = None
            try:
                if scheme == 'https':
                    ssl_sock = self.create_ssl_connection((realhost or host, port), self.max_timeout, validate=validate, cache_key=connection_cache_key)
                    if ssl_sock:
                        sock = ssl_sock.sock
                        del ssl_sock.sock
                    else:
                        raise socket.error('timed out', 'create_ssl_connection(%r,%r)' % (realhost or host, port))
                else:
                    sock = self.create_connection((realhost or host, port), self.max_timeout, cache_key=connection_cache_key)
                if sock:
                    if scheme == 'https':
                        crlf = 0
                    return self._request(ssl_sock or sock, method, path, self.protocol_version, headers, payload, bufsize=bufsize, crlf=crlf, return_sock=return_sock)
            except Exception as e:
                logging.debug('request "%s %s" failed:%s', method, url, e)
                if ssl_sock:
                    ssl_sock.close()
                if sock:
                    sock.close()
                if i == self.max_retry - 1:
                    raise
                else:
                    continue


class Common(object):
    """Global Config Object"""


    def __init__(self):
        """load config from proxy.ini"""
        ConfigParser.RawConfigParser.OPTCRE = re.compile(r'(?P<option>[^=\s][^=]*)\s*(?P<vi>[=])\s*(?P<value>.*)$')
        self.CONFIG = ConfigParser.ConfigParser()
        self.CONFIG_FILENAME = os.path.splitext(os.path.abspath(__file__))[0]+'.ini'
        self.CONFIG.read(self.CONFIG_FILENAME)

        self.LISTEN_IP = self.CONFIG.get('listen', 'ip')
        self.LISTEN_PORT = self.CONFIG.getint('listen', 'port')
        self.LISTEN_VISIBLE = self.CONFIG.getint('listen', 'visible')
        self.LISTEN_DEBUGINFO = self.CONFIG.getint('listen', 'debuginfo')
        logging.basicConfig(level=logging.DEBUG if self.LISTEN_DEBUGINFO else logging.WARNING, format='%(levelname)s - %(asctime)s %(message)s', datefmt='[%b %d %H:%M:%S]')

        self.GAE_PROFILE = self.CONFIG.get('gae', 'profile').strip()
        self.GAE_WINDOW = self.CONFIG.getint('gae', 'window')

        hosts_section, http_section = '%s/hosts' % self.GAE_PROFILE, '%s/http' % self.GAE_PROFILE
        self.HOSTS_MAP = collections.OrderedDict((k, v or k) for k, v in self.CONFIG.items(hosts_section) if '\\' not in k and ':' not in k and not k.startswith('.'))
        self.HOSTS_POSTFIX_MAP = collections.OrderedDict((k, v) for k, v in self.CONFIG.items(hosts_section) if '\\' not in k and ':' not in k and k.startswith('.'))
        self.HOSTS_POSTFIX_ENDSWITH = tuple(self.HOSTS_POSTFIX_MAP)

        self.CONNECT_HOSTS_MAP = collections.OrderedDict((k, v) for k, v in self.CONFIG.items(hosts_section) if ':' in k and not k.startswith('.'))
        self.CONNECT_POSTFIX_MAP = collections.OrderedDict((k, v) for k, v in self.CONFIG.items(hosts_section) if ':' in k and k.startswith('.'))
        self.CONNECT_POSTFIX_ENDSWITH = tuple(self.CONNECT_POSTFIX_MAP)

        self.METHOD_REMATCH_MAP = collections.OrderedDict((re.compile(k).match, v) for k, v in self.CONFIG.items(hosts_section) if '\\' in k)
        self.METHOD_REMATCH_HAS_LOCALFILE = any(x.startswith('file://') for x in self.METHOD_REMATCH_MAP.values())

        self.IPLIST_MAP = collections.OrderedDict((k, v.split('|')) for k, v in self.CONFIG.items('iplist'))
        self.IPLIST_MAP.update((k, [k]) for k, v in self.HOSTS_MAP.items() if k == v)

        self.FETCHMAX_LOCAL =  3
        self.FETCHMAX_SERVER = ''

        self.USERAGENT_ENABLE = self.CONFIG.getint('useragent', 'enable')
        self.USERAGENT_STRING = self.CONFIG.get('useragent', 'string')

    def resolve_iplist(self):
        def do_remote_resolve(host, dnsserver, queue):
            try:
                queue.put((host, dnsserver, DNSUtil.remote_resolve(dnsserver, host, timeout=2)))
            except (socket.error, OSError) as e:
                logging.error('resolve remote host=%r dnsserver=%r failed: %s', host, dnsserver, e)
        # https://support.google.com/websearch/answer/186669?hl=zh-Hans
        google_blacklist = ['nosslsearch.google.com', '216.239.32.20', '74.125.127.102', '74.125.155.102', '74.125.39.102', '74.125.39.113', '209.85.229.138']
        for host in google_blacklist[:]:
            if re.match(r'\d+\.\d+\.\d+\.\d+', host) or ':' in host:
                continue
            try:
                google_blacklist.remove(host)
                google_blacklist += socket.gethostbyname_ex(host)[-1]
            except socket.error as e:
                logging.warning('resolve google_blacklist from host=%r failed: %r', host, e)
        google_blacklist = list(set(google_blacklist))
        for name, need_resolve_hosts in list(self.IPLIST_MAP.items()):
            if all(re.match(r'\d+\.\d+\.\d+\.\d+', x) or ':' in x for x in need_resolve_hosts):
                continue
            resolved_iplist = []
            need_resolve_remote = []
            for host in need_resolve_hosts:
                if re.match(r'\d+\.\d+\.\d+\.\d+', host) or ':' in host:
                    resolved_iplist += [host]
                    continue
                try:
                    iplist = socket.gethostbyname_ex(host)[-1]
                    if name.startswith('google_'):
                        if len(iplist) >= 2:
                            resolved_iplist += iplist
                        else:
                            need_resolve_remote += [host]
                    else:
                        resolved_iplist += iplist
                except (socket.error, OSError):
                    need_resolve_remote += [host]
            if name != 'google_cn' and name.startswith('google_') and len(resolved_iplist) < 32:
                logging.info('local need_resolve_hosts=%s is too short, try remote_resolve', need_resolve_hosts)
                need_resolve_remote += [x for x in need_resolve_hosts if ':' not in x and not re.match(r'\d+\.\d+\.\d+\.\d+', x)]
            dnsservers = ['114.114.114.114', '114.114.115.115','1.2.4.8','210.2.4.8']
            result_queue = Queue.Queue()
            for host in need_resolve_remote:
                for dnsserver in dnsservers:
                    logging.debug('resolve remote host=%r from dnsserver=%r', host, dnsserver)
                    threading._start_new_thread(do_remote_resolve, (host, dnsserver, result_queue))
            for _ in xrange(len(need_resolve_remote) * len(dnsservers)):
                try:
                    host, dnsserver, iplist = result_queue.get(timeout=2)
                    resolved_iplist += iplist or []
                    logging.debug('resolve remote host=%r from dnsserver=%r return iplist=%s', host, dnsserver, iplist)
                except Queue.Empty:
                    logging.warn('resolve remote timeout, continue')
                    break
            if name.startswith('google_') and name not in ('google_cn', 'google_hk'):
                iplist_prefix = re.split(r'[\.:]', resolved_iplist[0])[0]
                resolved_iplist = list(set(x for x in resolved_iplist if x.startswith(iplist_prefix)))
            else:
                resolved_iplist = list(set(resolved_iplist))
            if name.startswith('google_'):
                resolved_iplist = list(set(resolved_iplist) - set(google_blacklist))
            if len(resolved_iplist) == 0:
                logging.error('resolve %s host return empty! please retry!', name)
                sys.exit(-1)
            logging.info('resolve name=%s host to iplist=%r', name, resolved_iplist)
            common.IPLIST_MAP[name] = resolved_iplist


    def info(self):
        info = ''
        info += '------------------------------------------------------\n'
        info += 'GreatAgent SimpleProxy Version	: %s (python/%s %spyopenssl/%s)\n' % (__version__, sys.version[:5], gevent and 'gevent/%s ' % gevent.__version__ or '', getattr(OpenSSL, '__version__', 'Disabled'))
        info += 'Uvent Version      : %s (pyuv/%s libuv/%s)\n' % (__import__('uvent').__version__, __import__('pyuv').__version__, __import__('pyuv').LIBUV_VERSION) if all(x in sys.modules for x in ('pyuv', 'uvent')) else ''
        info += 'Listen Address     : %s:%d\n' % (self.LISTEN_IP, self.LISTEN_PORT)
        info += 'Debug INFO         : %s\n' % self.LISTEN_DEBUGINFO if self.LISTEN_DEBUGINFO else ''
        info += '------------------------------------------------------\n'
        return info

common = Common()
http_util = HTTPUtil(max_window=common.GAE_WINDOW)


def message_html(title, banner, detail=''):
    MESSAGE_TEMPLATE = '''
    <html><head>
    <meta http-equiv="content-type" content="text/html;charset=utf-8">
    <title>$title</title>
    <style><!--
    body {font-family: arial,sans-serif}
    div.nav {margin-top: 1ex}
    div.nav A {font-size: 10pt; font-family: arial,sans-serif}
    span.nav {font-size: 10pt; font-family: arial,sans-serif; font-weight: bold}
    div.nav A,span.big {font-size: 12pt; color: #0000cc}
    div.nav A {font-size: 10pt; color: black}
    A.l:link {color: #6f6f6f}
    A.u:link {color: green}
    //--></style>
    </head>
    <body text=#000000 bgcolor=#ffffff>
    <table border=0 cellpadding=2 cellspacing=0 width=100%>
    <tr><td bgcolor=#3366cc><font face=arial,sans-serif color=#ffffff><b>Message</b></td></tr>
    <tr><td> </td></tr></table>
    <blockquote>
    <H1>$banner</H1>
    $detail
    <p>
    </blockquote>
    <table width=100% cellpadding=0 cellspacing=0><tr><td bgcolor=#3366cc><img alt="" width=1 height=4></td></tr></table>
    </body></html>
    '''
    return string.Template(MESSAGE_TEMPLATE).substitute(title=title, banner=banner, detail=detail)


class LocalProxyServer(SocketServer.ThreadingTCPServer):
    """Local Proxy Server"""
    allow_reuse_address = True

    def close_request(self, request):
        try:
            request.close()
        except Exception:
            pass

    def finish_request(self, request, client_address):
        try:
            self.RequestHandlerClass(request, client_address, self)
        except NetWorkIOError as e:
            if e[0] not in (errno.ECONNABORTED, errno.ECONNRESET, errno.EPIPE):
                raise

    def handle_error(self, *args):
        """make ThreadingTCPServer happy"""
        exc_info = sys.exc_info()
        error = exc_info and len(exc_info) and exc_info[1]
        if len(error.args) > 1:
            error_args = error.args[1]
        else:
            error_args = ''
        if isinstance(error, NetWorkIOError) and 'bad write retry' in error_args:
            exc_info = error = None
        else:
            del exc_info, error
            #SocketServer.ThreadingTCPServer.handle_error(self, *args)

class GAEProxyHandler(BaseHTTPServer.BaseHTTPRequestHandler):

    bufsize = 256*1024
    first_run_lock = threading.Lock()
    normcookie = functools.partial(re.compile(', ([^ =]+(?:=|$))').sub, '\\r\\nSet-Cookie: \\1')
    normattachment = functools.partial(re.compile(r'filename=([^"\']+)').sub, 'filename="\\1"')

    def first_run(self):
        """GAEProxyHandler setup, init domain/iplist map"""
        common.resolve_iplist()

    def setup(self):
        if isinstance(self.__class__.first_run, collections.Callable):
            try:
                with self.__class__.first_run_lock:
                    if isinstance(self.__class__.first_run, collections.Callable):
                        self.first_run()
                        self.__class__.first_run = None
            except Exception as e:
                logging.exception('GAEProxyHandler.first_run() return %r', e)
        self.__class__.setup = BaseHTTPServer.BaseHTTPRequestHandler.setup
        self.__class__.do_GET = self.__class__.do_METHOD
        self.__class__.do_PUT = self.__class__.do_METHOD
        self.__class__.do_POST = self.__class__.do_METHOD
        self.__class__.do_HEAD = self.__class__.do_METHOD
        self.__class__.do_DELETE = self.__class__.do_METHOD
        self.__class__.do_OPTIONS = self.__class__.do_METHOD
        self.setup()

    def finish(self):
        """make python2 BaseHTTPRequestHandler happy"""
        try:
            BaseHTTPServer.BaseHTTPRequestHandler.finish(self)
        except NetWorkIOError as e:
            if e[0] not in (errno.ECONNABORTED, errno.ECONNRESET, errno.EPIPE):
                raise

    def address_string(self):
        return '%s:%s' % self.client_address[:2]

    def do_METHOD(self):
        host = self.headers.get('Host', '')
        if self.path[0] == '/' and host:
            self.path = 'http://%s%s' % (host, self.path)
        elif not host and '://' in self.path:
            host = urlparse.urlparse(self.path).netloc
        self.url_parts = urlparse.urlparse(self.path)
        if common.USERAGENT_ENABLE:
            self.headers['User-Agent'] = common.USERAGENT_STRING
        return self.do_METHOD_FWD()

    def do_METHOD_FWD(self):
        """Direct http forward"""
        response = None
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            payload = self.rfile.read(content_length) if content_length else b''
            host = self.url_parts.netloc
            if any(x(self.path) for x in common.METHOD_REMATCH_MAP):
                hostname = next(common.METHOD_REMATCH_MAP[x] for x in common.METHOD_REMATCH_MAP if x(self.path))
            elif host in common.HOSTS_MAP:
                hostname = common.HOSTS_MAP[host]
            elif host.endswith(common.HOSTS_POSTFIX_ENDSWITH):
                hostname = next(common.HOSTS_POSTFIX_MAP[x] for x in common.HOSTS_POSTFIX_MAP if host.endswith(x))
                common.HOSTS_MAP[host] = hostname
            else:
                hostname = host
            if common.METHOD_REMATCH_HAS_LOCALFILE and hostname.startswith('file://'):
                filename = hostname.lstrip('file://')
                if os.name == 'nt':
                    filename = filename.lstrip('/')
                content_type = None
                try:
                    import mimetypes
                    content_type = mimetypes.types_map.get(os.path.splitext(filename)[1])
                except Exception as e:
                    logging.error('import mimetypes failed: %r', e)
                try:
                    with open(filename, 'rb') as fp:
                        data = fp.read()
                        self.wfile.write('HTTP/1.1 200\r\n')
                        self.wfile.write('Connection: close\r\n')
                        self.wfile.write('Content-Length: %s\r\n' % len(data))
                        if content_type:
                            self.wfile.write('Content-Type: %s\r\n' % content_type)
                        self.wfile.write('\r\n')
                        self.wfile.write(data)
                except Exception as e:
                    self.wfile.write('HTTP/1.1 403\r\n')
                    self.wfile.write('Connection: close\r\n')
                    self.wfile.write('\r\n')
                    self.wfile.write('open %r failed: %r' % (filename, e))
                finally:
                    logging.info('%r matched local file %r, return', self.path, filename)
                    return
            need_crlf = hostname.startswith('google_')
            hostname = hostname or host
            if hostname in common.IPLIST_MAP:
                http_util.dns[host] = common.IPLIST_MAP[hostname]
            else:
                http_util.dns[host] = sum((http_util.dns_resolve(x) for x in hostname.split('|')), [])
            validate = None
            connection_cache_key = None
            response = http_util.request(self.command, self.path, payload, self.headers, crlf=need_crlf, validate=validate, connection_cache_key=connection_cache_key)
            if not response:
                return
            logging.info('%s "FWD %s %s HTTP/1.1" %s %s', self.address_string(), self.command, self.path, response.status, response.getheader('Content-Length', '-'))
            if response.status in (400, 405):
                common.GAE_CRLF = 0
            if response.getheader('Set-Cookie'):
                response.msg['Set-Cookie'] = self.normcookie(response.getheader('Set-Cookie'))
            self.wfile.write(('HTTP/1.1 %s\r\n%s\r\n' % (response.status, ''.join('%s: %s\r\n' % (k.title(), v) for k, v in response.getheaders() if k.title() != 'Transfer-Encoding'))))
            while True:
                data = response.read(8192)
                if not data:
                    break
                self.wfile.write(data)
                del data
            response.close()
        except NetWorkIOError as e:
            if response:
                response.close()
            if e.args[0] in (errno.ECONNRESET, 10063, errno.ENAMETOOLONG):
                logging.warn('http_util.request "%s %s" failed:%s, try addto `withgae`', self.command, self.path, e)
            elif e.args[0] not in (errno.ECONNABORTED, errno.EPIPE):
                raise
        except Exception as e:
            host = self.headers.get('Host', '')
            logging.warn('GAEProxyHandler direct(%s) Error', host)
            print e

    def do_CONNECT(self):
        """handle CONNECT cmmand, socket forward or deploy a fake cert"""
        host, _, port = self.path.rpartition(':')
        return self.do_CONNECT_PROCESS()

    def do_CONNECT_PROCESS(self):
        """deploy fake cert to client"""
        host, _, port = self.path.rpartition(':')
        port = int(port)
        certfile = CertUtil.get_cert(host)
        logging.info('%s "PROCESS %s %s:%d HTTP/1.1" - -', self.address_string(), self.command, host, port)
        self.__realconnection = None
        self.wfile.write(b'HTTP/1.1 200 OK\r\n\r\n')
        for i in range(1, 3):
            try:
                ssl_sock = ssl.wrap_socket(self.connection, keyfile=certfile, certfile=certfile, server_side=True)
                break
            except Exception as e:
                continue
        self.__realconnection = self.connection
        self.__realwfile = self.wfile
        self.__realrfile = self.rfile
        self.connection = ssl_sock
        self.rfile = self.connection.makefile('rb', self.bufsize)
        self.wfile = self.connection.makefile('wb', 0)
        try:
            self.raw_requestline = self.rfile.readline(65537)
            if len(self.raw_requestline) > 65536:
                self.requestline = ''
                self.request_version = ''
                self.command = ''
                self.send_error(414)
                return
            if not self.raw_requestline:
                self.close_connection = 1
                return
            if not self.parse_request():
                return
        except NetWorkIOError as e:
            if e.args[0] not in (errno.ECONNABORTED, errno.ECONNRESET, errno.EPIPE):
                raise
        if self.path[0] == '/' and host:
            self.path = 'https://%s%s' % (self.headers['Host'], self.path)
        try:
            self.do_METHOD()
        except NetWorkIOError as e:
            if e.args[0] not in (errno.ECONNABORTED, errno.ETIMEDOUT, errno.EPIPE):
                raise
        finally:
            if self.__realconnection:
                try:
                    self.__realconnection.shutdown(socket.SHUT_WR)
                    self.__realconnection.close()
                except NetWorkIOError:
                    pass
                finally:
                    self.__realconnection = None


server = LocalProxyServer((common.LISTEN_IP, common.LISTEN_PORT), GAEProxyHandler)

