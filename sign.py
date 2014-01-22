#!/usr/bin/env python
# coding:utf-8
# sign.py
# Author: Wang Wei Qiang <wwqgtxx@gmail.com>

import sys
import os
import os
import glob

sys.path += glob.glob('%s/*.egg' % os.path.dirname(os.path.abspath(__file__)))
sys.path += glob.glob('%s/lib/*.egg' % os.path.dirname(os.path.abspath(__file__)))
import rsa
import base92
import time

try:
	if 'threading' in sys.modules:
		del sys.modules['threading']
	import gevent
	import gevent.socket
	import gevent.monkey
	gevent.monkey.patch_all()
except (ImportError, SystemError):
	gevent = None


from common import sysconfig as common
from common import FileUtil
from common import Config
from common import __config__
from common import __file__

def sign(message):
	#message = base92.encode(message)
	privatefile = FileUtil.open(common.CONFIG_PRIKEY,'r')
	keydata = privatefile.read()
	prikey = rsa.PrivateKey.load_pkcs1(keydata)
	signature = rsa.sign(message, prikey, 'SHA-1')
	return base92.encode(signature)
def verify(message,signature):
	#message = base92.encode(message)
	signature = base92.decode(signature)
	publicfile = FileUtil.open(common.CONFIG_PUBKEY,'r')
	keydata = publicfile.read()
	pubkey = rsa.PublicKey.load_pkcs1(keydata)
	try:
		rsa.verify(message,signature, pubkey)
		return True
	except rsa.pkcs1.VerificationError:
		return False
def make():
	(pubkey, privkey) = rsa.newkeys(2048)
	print pubkey.save_pkcs1()
	print '----------------------------------'
	print privkey.save_pkcs1()
	
def do(message,filename):
	FileUtil.if_has_file_remove(filename)
	output = FileUtil.open(filename,"w")
	output.write(sign(message))
	output.close()
	input = FileUtil.open(filename,"r")
	ok = verify(message,input.read())
	input.close()
	return ok
	
def version():
	input = FileUtil.open(common.CONFIG_GIT,"r")
	gits = input.read().replace('\r\n','\n').split('\n')
	input.close()
	message  = "=============================="
	message += "\r\n"
	message += "Name:"+common.CONFIG_NAMES
	message += "\r\n"
	message += "Author:"+common.CONFIG_AUTHOR
	message += "\r\n"
	message += "Version:"+common.CONFIG_VERSION
	message += "\r\n"
	message += "Now Git Version:"
	message += str(len(gits))
	message += "\r\n"
	message += "Last Git Commit:"
	message += gits[len(gits)-2]
	message += "\r\n"
	message += "Update Time:"
	message += time.strftime("%Y-%m-%d %X",time.localtime())
	message += "\r\n"
	message += "=============================="
	message += "\r\n"
	out = FileUtil.open(common.CONFIG_VERSIONFILE,"w")
	out.write(message)
	out.close
	return message

def main():
	dir = FileUtil.cur_file_dir()
	#print 'now dir : '+dir
	os.chdir(dir)
	input = open(common.CONFIG_SHA1,"r")
	sha1 = input.read()
	input.close()
	print 'Now Signing sha1.ini ...'
	if do(sha1,common.CONFIG_SIGN):
		print 'Sign OK!'
		print version()
	else:
		print 'Sign Fail!'
		sys.exit()




if __name__ == '__main__':
	main()