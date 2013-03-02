import ConfigParser

__config__   = 'proxy.ini'
__myconfig__ = 'myproxy.ini'
__file__     = 'getmyconfig.py'



class Common(object,__config__):

	def __init__(self):
		"""load config from proxy.ini"""
		ConfigParser.RawConfigParser.OPTCRE = re.compile(r'(?P<option>[^=\s][^=]*)\s*(?P<vi>[=])\s*(?P<value>.*)$')
		self.CONFIG = ConfigParser.ConfigParser()
		self.CONFIG.read(os.path.join(os.path.dirname(__file__), __config__))
		self.IPS = []


	def getfile(self,filename):
		global __file__
		__file__ = os.path.abspath(__file__)
		if os.path.islink(__file__):
			__file__ = getattr(os, 'readlink', lambda x:x)(__file__)
		os.chdir(os.path.dirname(os.path.abspath(__file__)))
		return os.path.join(os.path.dirname(__file__), filename)
		

	def writeconfig(self,section, option,str):
		self.CONFIG.set(section,option,str)
		f = open(self.getfile(__config__),'w') 
		self.CONFIG.write(f)
		f.close()
	
	def getconfig(self,section, option):
		return self.CONFIG.get(section, option)if self.CONFIG.has_option(section, option) else ''

def main():
	if os.path.isfile(self.getfile(__myconfig__)):
		config = Common(__config__)
		myconfig = Common(__myconfig__)
		config.writeconfig('listen','ip',myconfig.getconfig('listen','ip'))
		config.writeconfig('listen','port',myconfig.getconfig('listen','port'))
		config.writeconfig('listen','visible',myconfig.getconfig('listen','visible'))
		config.writeconfig('listen','debuginfo',myconfig.getconfig('listen','debuginfo'))
		config.writeconfig('proxy','enable',myconfig.getconfig('proxy','enable'))
		config.writeconfig('proxy','autodetect',myconfig.getconfig('proxy','autodetect'))
		config.writeconfig('proxy','host',myconfig.getconfig('proxy','host'))
		config.writeconfig('proxy','port',myconfig.getconfig('proxy','port'))
		config.writeconfig('proxy','username',myconfig.getconfig('proxy','username'))
		config.writeconfig('proxy','password',myconfig.getconfig('proxy','password'))

if __name__ == '__main__':
	main()