#!/usr/bin/env python
# coding:utf-8
# startbroswer.py
# Author: Wang Wei Qiang <wwqgtxx@gmail.com>

import os
import sys
import shutil
from common import FileUtil

def main():
	dir = FileUtil.cur_file_dir()
	os.chdir(dir)
	print 'Starting FirefoxPortable...'
	if FileUtil.has_file('FirefoxPortable/FirefoxPortable.exe'):
		os.system('start ./FirefoxPortable/FirefoxPortable.exe  -no-remote "https://greatagent-ifanqiang.googlecode.com/git-history/web/greatagent2-esr/ifanqiang.htm"')
		return
	else:
		print "Don't Have FirefoxPortable"
		FileUtil.delete_dir("FirefoxPortable")
	print 'Starting GoogleChromePortable...'
	if  FileUtil.has_file('GoogleChromePortable/GoogleChromePortable.exe'):
		os.system('start ./GoogleChromePortable/GoogleChromePortable.exe   --ignore-certificate-errors  "https://greatagent-ifanqiang.googlecode.com/git-history/web/greatagent2-esr/ifanqiang.htm"')
		return
	else:
		print "Don't Have GoogleChromePortable"
	print 'Starting OperaPortable...'
	if  FileUtil.has_file('OperaPortable/OperaPortable.exe'):
		os.system('start ./OperaPortable/OperaPortable.exe "https://greatagent-ifanqiang.googlecode.com/git-history/web/greatagent2-esr/ifanqiang.htm"')
		return
	else:
		print "Don't Have OperaPortable"
		print 'Starting MaxthonPortable...'
	if  FileUtil.has_file('MaxthonPortable/MaxthonPortable.exe'):
		os.system('start ./MaxthonPortable/MaxthonPortable.exe "https://greatagent-ifanqiang.googlecode.com/git-history/web/greatagent2-esr/ifanqiang.htm"')
		return
	else:
		print "Don't Have MaxthonPortable"
	print "Don't Have Any Portable Broswer!"

if __name__ == '__main__':
	main()