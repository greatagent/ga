#!/usr/bin/env python
# coding:utf-8
# Based on GoAgent 3.0.5 by Phus Lu <phus.lu@gmail.com>
# Author: Wang Wei Qiang <wwqgtxx@gmail.com>

__version__ = '1.0.0'

import sys
import os
import glob

sys.path += glob.glob('%s/*.egg' % os.path.dirname(os.path.abspath(__file__)))
sys.path += glob.glob('%s/lib/*.egg' % os.path.dirname(os.path.abspath(__file__)))

try:
	if 'threading' in sys.modules:
		del sys.modules['threading']
	import gevent
	import gevent.socket
	import gevent.monkey
	gevent.monkey.patch_all()
except (ImportError, SystemError):
	gevent = None
	
import errno
import time
import struct
import collections
import zlib
import functools
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

HAS_PYPY = hasattr(sys, 'pypy_version_info')
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
		traceback.print_exc(file=sys.stderr)

	def critical(self, fmt, *args, **kwargs):
		self.__set_error_color()
		self.log('CRITICAL', fmt, *args, **kwargs)
		self.__reset_color()
logging = sys.modules['logging'] = Logging('logging')

class Common(object):
	"""Global Config Object"""

	def __init__(self):
		"""load config from ini"""
		ConfigParser.RawConfigParser.OPTCRE = re.compile(r'(?P<option>[^=\s][^=]*)\s*(?P<vi>[=])\s*(?P<value>.*)$')
		self.CONFIG = ConfigParser.ConfigParser()
		self.CONFIG_FILENAME = os.path.splitext(os.path.abspath(__file__))[0]+'.ini'
		self.CONFIG.read(self.CONFIG_FILENAME)
		

		self.LISTEN_IP = self.CONFIG.get('listen', 'ip')
		self.LISTEN_PORT = self.CONFIG.getint('listen', 'port')
		self.LISTEN_VISIBLE = self.CONFIG.getint('listen', 'visible')
		self.LISTEN_DEBUGINFO = self.CONFIG.getint('listen', 'debuginfo') if self.CONFIG.has_option('listen', 'debuginfo') else 0

		self.GAE_PROFILE = self.CONFIG.get('google', 'profile')
		self.GAE_CRLF = self.CONFIG.getint('google', 'crlf')
		self.GAE_VALIDATE = self.CONFIG.getint('google', 'validate')
		self.GAE_OBFUSCATE = self.CONFIG.getint('google', 'obfuscate') if self.CONFIG.has_option('google', 'obfuscate') else 0
		self.GAE_USEFAKEHTTPS = self.CONFIG.getint('google', 'usefakehttps') if self.CONFIG.has_option('google', 'usefakehttps') else 0

		self.PROXY_ENABLE = self.CONFIG.getint('proxy', 'enable')
		self.PROXY_HOST = self.CONFIG.get('proxy', 'host')
		self.PROXY_PORT = self.CONFIG.getint('proxy', 'port')
		self.PROXY_USERNAME = self.CONFIG.get('proxy', 'username')
		self.PROXY_PASSWROD = self.CONFIG.get('proxy', 'password')

		if self.PROXY_ENABLE:
			self.GOOGLE_MODE = 'https'
			self.proxy = 'https://%s:%s@%s:%d' % (self.PROXY_USERNAME or '', self.PROXY_PASSWROD or '', self.PROXY_HOST, self.PROXY_PORT)
		else:
			self.proxy = ''

		self.GOOGLE_MODE = self.CONFIG.get(self.GAE_PROFILE, 'mode')
		self.GOOGLE_WINDOW = self.CONFIG.getint(self.GAE_PROFILE, 'window') if self.CONFIG.has_option(self.GAE_PROFILE, 'window') else 4
		self.GOOGLE_HOSTS = [x for x in self.CONFIG.get(self.GAE_PROFILE, 'hosts').split('|') if x]
		self.GOOGLE_SITES = tuple(x for x in self.CONFIG.get(self.GAE_PROFILE, 'sites').split('|') if x)

		self.USERAGENT_ENABLE = self.CONFIG.getint('useragent', 'enable')
		self.USERAGENT_STRING = self.CONFIG.get('useragent', 'string')
		self.FETCHMAX_LOCAL = 3
		self.FETCHMAX_SERVER = ''
		logging.basicConfig(level=logging.DEBUG if self.LISTEN_DEBUGINFO else logging.INFO, format='%(levelname)s - %(asctime)s %(message)s', datefmt='[%b %d %H:%M:%S]')
		
	def info(self):
		info = ''
		info += '------------------------------------------------------\n'
		info += 'GreatAgent SimpleProxy Version	: %s \n' % (__version__)
		info += 'Uvent Version	  : %s (pyuv/%s libuv/%s)\n' % (__import__('uvent').__version__, __import__('pyuv').__version__, __import__('pyuv').LIBUV_VERSION) if all(x in sys.modules for x in ('pyuv', 'uvent')) else ''
		info += 'Listen Address	 : %s:%d\n' % (self.LISTEN_IP, self.LISTEN_PORT)
		info += 'Local Proxy		: %s:%s\n' % (self.PROXY_HOST, self.PROXY_PORT) if self.PROXY_ENABLE else ''
		info += 'Debug INFO		 : %s\n' % self.LISTEN_DEBUGINFO if self.LISTEN_DEBUGINFO else ''
		info += 'GOOGLE Mode		   : %s\n' % self.GOOGLE_MODE
		info += 'GOOGLE Profile		: %s\n' % self.GAE_PROFILE
		info += 'GOOGLE Validate	   : %s\n' % self.GAE_VALIDATE if self.GAE_VALIDATE else ''
		info += 'GOOGLE Obfuscate	  : %s\n' % self.GAE_OBFUSCATE if self.GAE_OBFUSCATE else ''
		info += '------------------------------------------------------\n'
		return info


common = Common()

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
				if i < DNSUtil.max_retry-1:
					# UDP mode query
					sock = socket.socket(family=address_family, type=socket.SOCK_DGRAM)
					sock.settimeout(timeout)
					sock.sendto(data, (dnsserver, port))
					for i in range(DNSUtil.max_wait):
						data = sock.recv(512)
						if data and not DNSUtil.is_bad_reply(data):
							return data[2:]
						else:
							logging.debug('DNSUtil._remote_resolve(dnsserver=%r, %r) return poisoned udp data=%r', qname, dnsserver, data)
				else:
					# TCP mode query
					sock = socket.socket(family=address_family, type=socket.SOCK_STREAM)
					sock.settimeout(timeout)
					sock.connect((dnsserver, port))
					data = struct.pack('>h', len(data)) + data
					sock.send(data)
					rfile = sock.makefile('rb', 512)
					data = rfile.read(2)
					if not data:
						logging.debug('DNSUtil._remote_resolve(dnsserver=%r, %r) return bad tcp header data=%r', qname, dnsserver, data)
						continue
					data = rfile.read(struct.unpack('>h', data)[0])
					if data and not DNSUtil.is_bad_reply(data):
						return data[2:]
					else:
						logging.debug('DNSUtil._remote_resolve(dnsserver=%r, %r) return bad tcp data=%r', qname, dnsserver, data)
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
	def _get_cert(commonname, sans=()):
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
			return None
		else:
			with CertUtil.ca_lock:
				if os.path.exists(certfile):
					return certfile
				return CertUtil._get_cert(commonname, sans)

	@staticmethod
	def check_ca():
		#Check CA exists
		certdir = os.path.join(os.path.dirname(__file__), CertUtil.ca_certdir)
		if glob.glob('%s/*.key' % CertUtil.ca_certdir):
			for filename in glob.glob('%s/*.key' % CertUtil.ca_certdir):
				try:
					os.remove(filename)
					os.remove(os.path.splitext(filename)[0]+'.crt')
				except EnvironmentError:
					pass
		#Check Certs Dir
		if not os.path.exists(certdir):
			os.makedirs(certdir)



gevent_wait_read = gevent.socket.wait_read if 'gevent.socket' in sys.modules else lambda fd,t: select.select([fd], [], [fd], t)
gevent_wait_write = gevent.socket.wait_write if 'gevent.socket' in sys.modules else lambda fd,t: select.select([], [fd], [fd], t)
gevent_wait_readwrite = gevent.socket.wait_readwrite if 'gevent.socket' in sys.modules else lambda fd,t: select.select([fd], [fd], [fd], t)

class SSLConnection(object):

	def __init__(self, context, sock):
		self._context = context
		self._sock = sock
		self._connection = OpenSSL.SSL.Connection(context, sock)
		self._makefile_refs = 0

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
				gevent_wait_readwrite(self._sock.fileno(), timeout)

	def connect(self, *args, **kwargs):
		timeout = self._sock.gettimeout()
		while True:
			try:
				self._connection.connect(*args, **kwargs)
				break
			except (OpenSSL.SSL.WantReadError, OpenSSL.SSL.WantX509LookupError):
				sys.exc_clear()
				gevent_wait_read(self._sock.fileno(), timeout)
			except OpenSSL.SSL.WantWriteError:
				sys.exc_clear()
				gevent_wait_write(self._sock.fileno(), timeout)

	def send(self, data, flags=0):
		timeout = self._sock.gettimeout()
		while True:
			try:
				self._connection.send(data, flags)
				break
			except (OpenSSL.SSL.WantReadError, OpenSSL.SSL.WantX509LookupError):
				sys.exc_clear()
				gevent_wait_read(self._sock.fileno(), timeout)
			except OpenSSL.SSL.WantWriteError:
				sys.exc_clear()
				gevent_wait_write(self._sock.fileno(), timeout)
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
				gevent_wait_read(self._sock.fileno(), timeout)
			except OpenSSL.SSL.WantWriteError:
				sys.exc_clear()
				gevent_wait_write(self._sock.fileno(), timeout)
			except OpenSSL.SSL.ZeroReturnError:
				return ''

	def read(self, bufsiz, flags=0):
		return self.recv(bufsiz, flags)

	def write(self, buf, flags=0):
		return self.sendall(buf, flags)

	def close(self):
		if self._makefile_refs < 1:
			self._connection = None
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

	def __init__(self, max_window=4, max_timeout=16, max_retry=4, proxy='', ssl_validate=False, ssl_obfuscate=False):
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
		self.ssl_connection_time = collections.defaultdict(float)
		self.max_timeout = max_timeout
		self.dns = {}
		self.crlf = 0
		self.proxy = proxy
		self.ssl_validate = ssl_validate or self.ssl_validate
		self.ssl_obfuscate = ssl_obfuscate or self.ssl_obfuscate
		if self.ssl_validate or self.ssl_obfuscate:
			self.ssl_context = OpenSSL.SSL.Context(OpenSSL.SSL.TLSv1_METHOD)
		else:
			self.ssl_context = None
		if self.ssl_validate:
			self.ssl_context.load_verify_locations(r'cacert.pem')
			self.ssl_context.set_verify(OpenSSL.SSL.VERIFY_PEER, lambda c, x, e, d, ok: ok)
		if self.ssl_obfuscate:
			self.ssl_ciphers = ':'.join(x for x in self.ssl_ciphers.split(':') if random.random() > 0.5)
			self.ssl_context.set_cipher_list(self.ssl_ciphers)

	def dns_resolve(self, host, dnsserver='', ipv4_only=True):
		iplist = self.dns.get(host)
		if not iplist:
			if not dnsserver:
				iplist = list(set(socket.gethostbyname_ex(host)[-1]) - DNSUtil.blacklist)
			else:
				iplist = DNSUtil.remote_resolve(dnsserver, host, timeout=2)
			if not iplist:
				iplist = DNSUtil.remote_resolve('8.8.8.8', host, timeout=2)
			if ipv4_only:
				iplist = [ip for ip in iplist if re.match(r'\d+\.\d+\.\d+\.\d+', ip)]
			self.dns[host] = iplist = list(set(iplist))
		return iplist

	def create_connection(self, address, timeout=None, source_address=None):
		def _create_connection(address, timeout, queobj):
			sock = None
			try:
				# create a ipv4/ipv6 socket object
				sock = socket.socket(socket.AF_INET if ':' not in address[0] else socket.AF_INET6)
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
				sock.connect(address)
				# record TCP connection time
				self.tcp_connection_time[address] = time.time() - start_time
				# put ssl socket object to output queobj
				queobj.put(sock)
			except (socket.error, ssl.SSLError, OSError) as e:
				# any socket.error, put Excpetions to output queobj.
				queobj.put(e)
				# reset a large and random timeout to the address
				self.tcp_connection_time[address] = self.max_timeout+random.random()
				# close tcp socket
				if sock:
					sock.close()

		def _close_connection(count, queobj):
			for _ in range(count):
				queobj.get()
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
			addrs = addresses[:window] + random.sample(addresses, window)
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
						logging.debug('create_connection to %s return %r, try again.', addrs, result)

	def create_ssl_connection(self, address, timeout=None, source_address=None):
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
				ssl_sock = ssl.wrap_socket(sock, do_handshake_on_connect=False)
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
				self.tcp_connection_time[ipaddr] = connected_time - start_time
				# record SSL connection time
				self.ssl_connection_time[ipaddr] = handshaked_time - start_time
				# sometimes, we want to use raw tcp socket directly(select/epoll), so setattr it to ssl socket.
				ssl_sock.sock = sock
				# verify SSL certificate.
				if self.ssl_validate and address[0].endswith('.appspot.com'):
					cert = ssl_sock.getpeercert()
					commonname = next((v for ((k, v),) in cert['subject'] if k == 'commonName'))
					if '.google' not in commonname and not commonname.endswith('.appspot.com'):
						raise ssl.SSLError("Host name '%s' doesn't match certificate host '%s'" % (address[0], commonname))
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
				ssl_sock = SSLConnection(self.ssl_context, sock)
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
				self.tcp_connection_time[ipaddr] = connected_time - start_time
				# record SSL connection time
				self.ssl_connection_time[ipaddr] = handshaked_time - start_time
				# sometimes, we want to use raw tcp socket directly(select/epoll), so setattr it to ssl socket.
				ssl_sock.sock = sock
				# verify SSL certificate.
				if self.ssl_validate and address[0].endswith('.appspot.com'):
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
		def _close_ssl_connection(count, queobj):
			for _ in range(count):
				queobj.get()
		host, port = address
		result = None
		create_connection = _create_ssl_connection if not self.ssl_obfuscate and not self.ssl_validate else _create_openssl_connection
		addresses = [(x, port) for x in self.dns_resolve(host)]
		for i in range(self.max_retry):
			window = min((self.max_window+1)//2 + i, len(addresses))
			addresses.sort(key=self.ssl_connection_time.__getitem__)
			addrs = addresses[:window] + random.sample(addresses, window)
			queobj = Queue.Queue()
			for addr in addrs:
				thread.start_new_thread(create_connection, (addr, timeout, queobj))
			for i in range(len(addrs)):
				result = queobj.get()
				if not isinstance(result, Exception):
					thread.start_new_thread(_close_ssl_connection, (len(addrs)-i-1, queobj))
					return result
				else:
					if i == 0:
						# only output first error
						logging.debug('create_ssl_connection to %s return %r, try again.', addrs, result)

	def create_connection_withdata(self, address, timeout=None, source_address=None, data=None):
		assert isinstance(data, str) and data
		host, port = address
		# result = None
		addresses = [(x, port) for x in self.dns_resolve(host)]
		if port == 443:
			get_connection_time = lambda addr: self.ssl_connection_time.get(addr) or self.tcp_connection_time.get(addr)
		else:
			get_connection_time = self.tcp_connection_time.get
		for i in range(self.max_retry):
			window = min((self.max_window+1)//2 + i, len(addresses))
			addresses.sort(key=get_connection_time)
			addrs = addresses[:window] + random.sample(addresses, window)
			socks = []
			for addr in addrs:
				sock = socket.socket(socket.AF_INET if ':' not in address[0] else socket.AF_INET6)
				sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
				sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 32*1024)
				sock.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, True)
				sock.setblocking(0)
				sock.connect_ex(addr)
				socks.append(sock)
			# something happens :D
			(_, outs, _) = select.select([], socks, [], 5)
			if outs:
				sock = outs[0]
				sock.setblocking(1)
				socks.remove(sock)
				any(s.close() for s in socks)
				return sock

	def create_connection_withproxy(self, address, timeout=None, source_address=None, proxy=None):
		assert isinstance(proxy, str)
		host, port = address
		try:
			try:
				self.dns_resolve(host)
			except (socket.error, OSError):
				pass
			proxyhost, _, proxyport = address.rpartition(':')
			sock = socket.create_connection((proxyhost, int(proxyport)))
			hostname = random.choice(self.dns.get(host) or [host if not host.endswith('.appspot.com') else 'www.google.com'])
			request_data = 'CONNECT %s:%s HTTP/1.1\r\n' % (hostname, port)
			if username and password:
				request_data += 'Proxy-authorization: Basic %s\r\n' % base64.b64encode(('%s:%s' % (username, password)).encode()).decode().strip()
			request_data += '\r\n'
			sock.sendall(request_data)
			response = httplib.HTTPResponse(sock)
			response.begin()
			if response.status >= 400:
				logging.error('create_connection_withproxy return http error code %s', response.status)
				sock = None
			return sock
		except Exception as e:
			logging.error('create_connection_withproxy error %s', e)
			raise

	def forward_socket(self, local, remote, timeout=60, tick=2, bufsize=8192, maxping=None, maxpong=None, pongcallback=None, bitmask=None):
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
						if bitmask:
							data = ''.join(chr(ord(x) ^ bitmask) for x in data)
						if data:
							if sock is remote:
								local.sendall(data)
								timecount = maxpong or timeout
								if pongcallback:
									try:
										#remote_addr = '%s:%s'%remote.getpeername()[:2]
										pongcallback()
									except Exception as e:
										logging.debug('remote=%s pongcallback=%s failed: %s', remote, pongcallback, e)
									finally:
										pongcallback = None
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

	def green_forward_socket(self, local, remote, timeout=60, tick=2, bufsize=8192, maxping=None, maxpong=None, pongcallback=None, bitmask=None):
		def io_copy(dest, source):
			try:
				dest.settimeout(timeout)
				source.settimeout(timeout)
				while 1:
					data = source.recv(bufsize)
					if not data:
						break
					if bitmask:
						data = ''.join(chr(ord(x) ^ bitmask) for x in data)
					dest.sendall(data)
			except NetWorkIOError as e:
				if e.args[0] not in ('timed out', errno.ECONNABORTED, errno.ECONNRESET, errno.EBADF, errno.EPIPE, errno.ENOTCONN, errno.ETIMEDOUT):
					raise
			finally:
				if local:
					local.close()
				if remote:
					remote.close()
		thread.start_new_thread(io_copy, (remote.dup(), local.dup()))
		io_copy(local, remote)

	def _request(self, sock, method, path, protocol_version, headers, payload, bufsize=8192, crlf=None, return_sock=None):
		skip_headers = self.skip_headers
		need_crlf = http_util.crlf
		if crlf:
			need_crlf = 1
		if need_crlf:
			request_data = 'GET / HTTP/1.1\r\n\r\n\r\n'
		else:
			request_data = ''
		request_data += '%s %s %s\r\n' % (method, path, protocol_version)
		request_data += ''.join('%s: %s\r\n' % (k, v) for k, v in headers.items() if k not in skip_headers)
		if self.proxy:
			_, username, password, _ = ProxyUtil.parse_proxy(self.proxy)
			if username and password:
				request_data += 'Proxy-Authorization: Basic %s\r\n' % base64.b64encode(('%s:%s' % (username, password)).encode()).decode().strip()
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

		response = httplib.HTTPResponse(sock)
		try:
			response.begin()
		except httplib.BadStatusLine:
			response = None
		return response

	def request(self, method, url, payload=None, headers={}, realhost='', fullurl=False, bufsize=8192, crlf=None, return_sock=None):
		scheme, netloc, path, _, query, _ = urlparse.urlparse(url)
		if netloc.rfind(':') <= netloc.rfind(']'):
			# no port number
			host = netloc
			port = 443 if scheme == 'https' else 80
		else:
			host, _, port = netloc.rpartition(':')
			port = int(port)
		path += '?' + query

		if 'Host' not in headers:
			headers['Host'] = host

		for i in range(self.max_retry):
			sock = None
			ssl_sock = None
			try:
				if not self.proxy:
					if scheme == 'https':
						ssl_sock = self.create_ssl_connection((realhost or host, port), self.max_timeout)
						if ssl_sock:
							sock = ssl_sock.sock
							del ssl_sock.sock
						else:
							raise socket.error('timed out', 'create_ssl_connection(%r,%r)' % (realhost or host, port))
					else:
						sock = self.create_connection((realhost or host, port), self.max_timeout)
				else:
					sock = self.create_connection_withproxy((realhost or host, port), port, self.max_timeout, proxy=self.proxy)
					path = url
					#crlf = self.crlf = 0
					if scheme == 'https':
						sock = SSLConnection(self.ssl_context, sock)
						sock.set_connect_state()
						sock.do_handshake()
				if sock:
					if scheme == 'https':
						crlf = 0
					return self._request(ssl_sock or sock, method, path, self.protocol_version, headers, payload, bufsize=bufsize, crlf=crlf, return_sock=return_sock)
			except Exception as e:
				if ssl_sock:
					ssl_sock.close()
				if sock:
					sock.close()
				if i == self.max_retry - 1:
					raise
				else:
					continue

http_util = HTTPUtil(max_window=common.GOOGLE_WINDOW, ssl_validate=common.GAE_VALIDATE , ssl_obfuscate=common.GAE_OBFUSCATE, proxy=common.proxy)
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
		etype, value, tb = sys.exc_info()
		if isinstance(value, NetWorkIOError) and 'bad write retry' in value.args[1]:
			etype = value = tb = None
		else:
			del etype, value, tb
			SocketServer.ThreadingTCPServer.handle_error(self, *args)


class GAEProxyHandler(BaseHTTPServer.BaseHTTPRequestHandler):

	bufsize = 256*1024
	first_run_lock = threading.Lock()

	def _update_google_iplist(self):
		if any(not re.match(r'\d+\.\d+\.\d+\.\d+', x) for x in common.GOOGLE_HOSTS):
			google_ipmap = {}
			need_resolve_remote = []
			for domain in common.GOOGLE_HOSTS:
				if not re.match(r'\d+\.\d+\.\d+\.\d+', domain):
					try:
						iplist = socket.gethostbyname_ex(domain)[-1]
						if len(iplist) >= 2:
							google_ipmap[domain] = iplist
					except (socket.error, OSError):
						need_resolve_remote.append(domain)
						continue
				else:
					google_ipmap[domain] = [domain]
			google_iplist = list(set(sum(list(google_ipmap.values()), [])))
			if len(google_iplist) < 10 or len(set(x.split('.', 1)[0] for x in google_iplist)) == 1:
				logging.debug('local google_iplist=%s is too short, try remote_resolve', google_iplist)
				need_resolve_remote += list(common.GOOGLE_HOSTS)
			for dnsserver in ('8.8.8.8', '8.8.4.4', '114.114.114.114', '114.114.115.115'):
				for domain in need_resolve_remote:
					logging.debug('resolve remote domain=%r from dnsserver=%r', domain, dnsserver)
					try:
						iplist = DNSUtil.remote_resolve(dnsserver, domain, timeout=3)
						if iplist:
							google_ipmap.setdefault(domain, []).extend(iplist)
							logging.debug('resolve remote domain=%r to iplist=%s', domain, google_ipmap[domain])
					except (socket.error, OSError) as e:
						logging.exception('resolve remote domain=%r dnsserver=%r failed: %s', domain, dnsserver, e)
			common.GOOGLE_HOSTS = list(set(sum(list(google_ipmap.values()), [])))
			if len(common.GOOGLE_HOSTS) == 0:
				logging.error('resolve %s domain return empty! try remote dns resovle!', common.GAE_PROFILE)
				common.GOOGLE_HOSTS = common.CONFIG.get(common.GAE_PROFILE, 'hosts').split('|')
				#sys.exit(-1)
		logging.debug('resolve common.GOOGLE_HOSTS domain to iplist=%r', common.GOOGLE_HOSTS)

	def first_run(self):
		"""GAEProxyHandler setup, init domain/iplist map"""
		if not common.PROXY_ENABLE:
			logging.debug('resolve common.GOOGLE_HOSTS domain=%r to iplist', common.GOOGLE_HOSTS)
			if common.GAE_PROFILE == 'google_cn':
				hosts = ('www.google.cn', 'www.g.cn','ditu.google.cn',"www.google-analytics.com","ssl.google-analytics.com","www.google.com","mail.google.com","www.android.com")
				iplist = []
				for host in hosts:
					try:
						ips = socket.gethostbyname_ex(host)[-1]
						if len(ips) > 1:
							iplist += ips
					except (socket.error, OSError) as e:
						logging.error('socket.gethostbyname_ex(host=%r) failed:%s', host, e)
				if len(common.GOOGLE_HOSTS) > 0: 
					prefix = re.sub(r'\d+\.\d+$', '', random.choice(common.GOOGLE_HOSTS))
				else :
					prefix = ''
				iplist = [x for x in iplist if x.startswith(prefix) and re.match(r'\d+\.\d+\.\d+\.\d+', x)]
				if iplist and len(iplist) > len(hosts):
					common.GOOGLE_HOSTS = list(set(iplist))
				# OK, let's test google_cn iplist and decide whether to switch
				need_switch = False
				sample_hosts = random.sample(list(common.GOOGLE_HOSTS), min(4, len(common.GOOGLE_HOSTS)))
				connect_timing = 0
			self._update_google_iplist()

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
		if HAS_PYPY:
			self.path = re.sub(r'(://[^/]+):\d+/', '\\1/', self.path)
		host = self.headers.get('Host', '')
		if self.path[0] == '/' and host:
			self.path = 'http://%s%s' % (host, self.path)
		elif not host and '://' in self.path:
			host = urlparse.urlparse(self.path).netloc
		self.parsed_url = urlparse.urlparse(self.path)

		if common.USERAGENT_ENABLE:
			self.headers['User-Agent'] = common.USERAGENT_STRING


		if host.endswith(common.GOOGLE_SITES):
			if host not in http_util.dns:
				#http_util.dns[host] = http_util.dns.default_factory(http_util.dns_resolve(host))
				http_util.dns[host] = list(set(common.GOOGLE_HOSTS))


		self.do_METHOD_FWD()


	def do_METHOD_FWD(self):
		"""Direct http forward"""
		try:
			content_length = int(self.headers.get('Content-Length', 0))
			payload = self.rfile.read(content_length) if content_length else b''
			response = http_util.request(self.command, self.path, payload, self.headers, crlf=common.GAE_CRLF)
			if not response:
				return
			logging.debug('%s "FWD %s %s HTTP/1.1" %s %s', self.address_string(), self.command, self.path, response.status, response.getheader('Content-Length', '-'))
			if response.status in (400, 405):
				common.GAE_CRLF = 0
			self.wfile.write(('HTTP/1.1 %s\r\n%s\r\n' % (response.status, ''.join('%s: %s\r\n' % (k.title(), v) for k, v in response.getheaders() if k.title() != 'Transfer-Encoding'))))
			while 1:
				data = response.read(8192)
				if not data:
					break
				self.wfile.write(data)
			response.close()
		except NetWorkIOError as e:
			if e.args[0] in (errno.ECONNRESET, 10063, errno.ENAMETOOLONG):
				logging.warn('http_util.request "%s %s" failed:%s, try addto `withgae`', self.command, self.path, e)
			elif e.args[0] not in (errno.ECONNABORTED, errno.EPIPE):
				raise
		except Exception as e:
			host = self.headers.get('Host', '')
			logging.warn('GAEProxyHandler direct(%s) Error', host)
			raise

	def do_CONNECT(self):
		"""handle CONNECT cmmand, socket forward or deploy a fake cert"""
		host = self.path.rpartition(':')[0]
		if common.GAE_USEFAKEHTTPS:
			if host.endswith(common.GOOGLE_SITES):
				http_util.dns[host] = common.GOOGLE_HOSTS
			self.do_CONNECT_PROCESS()
		else:
			self.do_CONNECT_FWD()

	def do_CONNECT_FWD(self):
		"""socket forward for http CONNECT command"""
		host, _, port = self.path.rpartition(':')
		port = int(port)
		logging.debug('%s "FWD %s %s:%d HTTP/1.1" - -', self.address_string(), self.command, host, port)
		#http_headers = ''.join('%s: %s\r\n' % (k, v) for k, v in self.headers.items())
		if not common.PROXY_ENABLE:
			self.wfile.write(b'HTTP/1.1 200 OK\r\n\r\n')
			data = self.connection.recv(1024)
			for i in range(5):
				try:
					timeout = 4
					remote = http_util.create_connection((host, port), timeout)
					if remote is not None and data:
						remote.sendall(data)
						break
					elif i == 0:
						# only print first create_connection error
						logging.error('http_util.create_connection((host=%r, port=%r), %r) timeout', host, port, timeout)
				except NetWorkIOError as e:
					if e.args[0] == 9:
						logging.error('GAEProxyHandler direct forward remote (%r, %r) failed', host, port)
						continue
					else:
						raise
			if hasattr(remote, 'fileno'):
				# reset timeout default to avoid long http upload failure, but it will delay timeout retry :(
				remote.settimeout(None)
				http_util.forward_socket(self.connection, remote, bufsize=self.bufsize)
		else:
			hostip = random.choice(http_util.dns_resolve(host))
			remote = http_util.create_connection_withproxy((hostip, int(port)), proxy=common.proxy)
			if not remote:
				logging.error('GAEProxyHandler proxy connect remote (%r, %r) failed', host, port)
				return
			self.wfile.write(b'HTTP/1.1 200 OK\r\n\r\n')
			http_util.forward_socket(self.connection, remote, bufsize=self.bufsize)

	def do_CONNECT_PROCESS(self):
		"""deploy fake cert to client"""
		host, _, port = self.path.rpartition(':')
		port = int(port)
		certfile = CertUtil.get_cert(host)
		logging.debug('%s "PROCESS %s %s:%d HTTP/1.1" - -', self.address_string(), self.command, host, port)
		self.__realconnection = None
		self.wfile.write(b'HTTP/1.1 200 OK\r\n\r\n')
		try:
			if not http_util.ssl_validate and not http_util.ssl_obfuscate:
				ssl_sock = ssl.wrap_socket(self.connection, keyfile=certfile, certfile=certfile, server_side=True)
			else:
				ssl_context = OpenSSL.SSL.Context(OpenSSL.SSL.TLSv1_METHOD)
				ssl_context.use_privatekey_file(certfile)
				ssl_context.use_certificate_file(certfile)
				ssl_sock = SSLConnection(ssl_context, self.connection)
				ssl_sock.set_accept_state()
				ssl_sock.do_handshake()
		except Exception as e:
			if e.args[0] not in (errno.ECONNABORTED, errno.ECONNRESET):
				logging.exception('ssl.wrap_socket(self.connection=%r) failed: %s', self.connection, e)
			return
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

