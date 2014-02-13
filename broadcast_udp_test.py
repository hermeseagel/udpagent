import datetime,threading,socket,os,sys,re,shutil,zipfile,subprocess,platform,fileinput
from ftplib import FTP
#check build version 
'''
def	 logwrite(info):
	if os.path.isdir('z:\\logs\')==True:
		dest='z:\\logs\'
		logformat=platform.node()+'-'＋datetime.datetime.now().strftime('%b-%d-%I%M%p-%G')+'.log'
		wf=os.open(logformat, 'w')
		info2=datetime.datetime.now()+'  '+info
		os.write(wf,info2) 
	else:
		os.makedir('z:\\logs\')

'''
def open_file_get_version(filename):
	if os.path.isfile(filename):
		versionfile=open(filename,'r')
		version=versionfile.readline()
		#print(version)
		#re usage and method descripe 
		versionnumber=re.findall(r"VERSION=(\d+.\d+.\d+)",version)
		print(versionnumber)
		versionfile.close()
		return True
	else:
		print('version file not exists')
		return False
	return versionnumber
		
#def send_log_to_admin(msg,ip):
#function to move current old build to another directory 
#move current build to archive 
def move_prev_build(source_dir,destion_dir):
	destdir=destion_dir
	print(destdir)
	shutil.copytree(source_dir,destdir)
	shutil.rmtree(source_dir)
	os.makedirs(source_dir)
	
	#shutil.move(source_dir,destdir)
#unzip agent build zip 
def extract_new_build(zipsource,destdir):
	global zipextractmsg
	try:
		zipdata = zipfile.ZipFile(zipsource)
		zipinfo = zipdata.infolist()
		zipdata.extractall(destdir)
		zipdata.close()
		zipextractmsg='extract zip OK'
	except exceptions as zipextractmsg:
		print(zipextractmsg)
	return zipextractmsg
#kill agent process  	
def kill_exist_agentp():
	try:
		subprocess.Popen('taskkill /f /fi "imagename eq wrapper*"')
		subprocess.Popen('taskkill /f /fi "imagename eq java*"')
	#subprocess.Popen('taskkill /f /fi "imagename eq cmd.exe"')
		killmsg='JAVA AND WRAPPER* PROCESS killed'
	except (OSError,ValueError) as killmsg:
		print(killmsg)
	return killmsg
#futrue function for use ftp to download and upload 
def get_build_from_ftp(ftpserve,ftp_user,ftp_pw,buildname,source,dst):
	try:
		file_tmp=dst+buildname
		ft=open(file_tmp,"wb")
		ftpconnect = FTP(ftpserver)
		ftpconnect.login(ftp_user,ftp_pw)
		ftpconnect.cwd(source)
		ftpconnect.retrbinary("RETR %s"%buildname, f, 8192)
	except (socket.error,socket.gaierror) as ftperror_msg:
		print(ftperror_msg)
def call_gps_agent(destdir):
	os.chdir(destdir)
	filename=destdir+'\\'+'1_agent.bat'
	print(filename)
	if os.path.isfile(filename) == True:
		os.system('start 1_agent.bat')
		agent_mesg=('start agent')
		print(agent_mesg)
	else:
		agent_mesg=('1_agent not exist')
		print(agent_mesg)
	return agent_mesg
#just allow encryptdisk write 	
def allow_encryptdisk():
	global allowdiskmsg
	try:
		subprocess.Popen("NET SHARE ubitus=k:\\gc /GRANT:ubitus,FULL")
		allowdiskmsg="allowed disk write"
	except (OSError,ValueError) as allowdiskmsg:
		print(allowdiskmsg)
	return allowdiskmsg
#turn off encrypdisk write privallege 
def disallow_encryptdisk():
	try:
		subprocess.Popen("NET SHARE ubitus /del")
		disallowmsg='disallowed disk write'
	except (OSError,ValueError) as disallowmsg:
		print(disallowmsg)
	return disallowmsg
def parsernetwork(msg,ipaddr):
	try:
		global Statflag,buildsource,zipfilename,version,ftpip,project_init,game_source,game_dest
		Statflag=''
		buildsource=''
		project_init=''
		ftpip=''
		zipfilename=''
		version=''
		game_source=''
		game_dest=''
		stra=str(msg,'utf-8')
		print('Stra:',stra)
		networkmsg=tuple(stra.split(','))
		print('networkmsg_tuple',networkmsg)
		for number in range(len(networkmsg)):
			msg=str(networkmsg[number])
			flag=msg.rsplit('=')
			#parameter=tuple(flag)
			#print(number)
			#print(flag,len(flag))
			if str(flag[0]) == ('status') and len(flag)==2:
				Statflag=flag[1]
			elif str(flag[0]) == ('source') and len(flag)==2:
				buildsource = flag[1]
			elif str(flag[0]) == ('ftpip') and len(flag)==2:
				ftpip=str(flag[1]).strip('()')
		
			elif str(flag[0]) == ('zipfile') and len(flag)==2:
				zipfilename=flag[1]
		
			elif str(flag[0]) == ('buildversion') and len(flag)==2:
				version=flag[1]
			
			elif str(flag[0]) == ('project') and len(flag)==2:
				project_init=flag[1] 
			elif str(flag[0]) == ('game_src') and len(flag)==2:
				game_source=flag[1]
			elif str(flag[0]) == ('game_dst') and len(flag)==2:
				game_dst=flag[1]
			else:
				txt='paratemers   unknow'+str(flag)
				msg=bytes(txt,'utf-8')
	except (IOError, os.error) as why:
		print(why)
			
def create_boardcast(addr,port):
	global mesag,hostname,hostip,defaultdest,c_socket,mesag,tempmsg
	mesag=''
	tempmsg=''
	defaultassembly='K:\\GC\\assembly\\'
	defaultoldsurce='K:\\GC\\build\\'
	#default_current=project_init+'_'+'ALL'
	try:
		print('begin create socket')
		c_socket=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		c_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		c_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
		print('begin bind ip and port ')
		c_socket.bind((addr,port))
		
		print('waiting connect')
	except (OSError) as connecterror:
		print(connecterror)
	try:
		while 1:
			try:
				mesag, send_addr=c_socket.recvfrom(8192)
			except (OSError) as socket_error:
				print('recvice_error',socke_error)
			print('server recevied %r from %r' % (str(mesag), send_addr) )
			parsernetwork(mesag,addr)
			hostname=socket.gethostname()
			localipaddr = socket.gethostbyname(hostname)
			ipinfo=hostname+','+localipaddr
			try:
				print('project_init len:',project_init,len(project_init))
				print('zipfilename len:',zipfilename,len(zipfilename))
				print('buildsource len:',buildsource,len(buildsource))
				print('version len:',version,len(version))
				if Statflag==('init') and len(project_init) > 1 and len(zipfilename)>1 and len(buildsource) >1 and len(version) >1:
					hostname=socket.gethostname()
					localipaddr = socket.gethostbyname(hostname)
					mesg=hostname+','+localipaddr
					msg=bytes(mesg,'utf-8')
					project=project_init+'-'+'assembly-all'
					destdir='K:\\GC\\'+project
					if os.path.isdir('K:\\')== True and os.path.isdir('K:\\GC\\') == False:
						allow_encryptdisk()
						os.makedirs('K:\\GC')
						os.makedirs(destdir)
						os.makedirs(defaultoldsurce)
						os.makedirs(defaultassembly)
						tempmsg='create GC,build,assembly directy'
					filename='K:\\'+project+'\\assembly-version'
					print(filename,',',project)
					sourcezip=buildsource+zipfilename
					if os.path.isfile(sourcezip)== True:
						shutil.copy(sourcezip,defaultassembly)
					else:
						msg='SOURCE file is not exist'
						c_socket.sendto(msg,send_addr)
						pass
					local_zip=defaultassembly+zipfilename
					print('zipfile',local_zip)
					extract_new_build(local_zip,destdir)
					disallow_encryptdisk()
					call_gps_agent(destdir)
					reply_info=tempmsg+','+zipextractmsg+','+allowdiskmsg
					msg=bytes(reply_info,'utf-8')
					c_socket.sendto(msg,send_addr)
				elif Statflag==('change_build') and len(zipfilename) >1 and len(project_init) >1 and len(buildsource) >1:
					print("begin change build")
					project=project_init+'-'+'assembly-all'
					currentbuild='K:\\GC\\'+project+'\\assembly-version'
					currentdir='K:\\GC\\'+project
					zipdest='K:\\GC\\'+project
					print(currentbuild,',',project)
					sourcezip=buildsource+zipfilename
					allow_encryptdisk()
					open_file_get_version(currentbuild)
					print('Version number',version)
					#move previous build to g:\\gc\\build with project
					arch_dest=defaultoldsurce+project+'-'+version
					new_build_dest='G:\\'+project
					print('new_build_dest:',new_build_dest)
					print('arch_dest:',arch_dest)
					#kill java wrap process
					kill_exist_agentp()
					#first stop Agent 							#then move previous build to G:\\GC\\BUILD\\
					print("move old build to G:\\GC\\BUILD\\")
					move_prev_build(currentdir,arch_dest)
					#copy newbuild from nas to G:\\GC\assembly
					print("move",sourcezip,"to",defaultassembly)
					shutil.copy(sourcezip,defaultassembly)
					#find local assembly
					local_zip=defaultassembly+zipfilename
					print('zipfile',local_zip)
					print('dest_dir:',zipdest)
					print('unzip agent.zip')
					extract_new_build(local_zip,zipdest)
					print('call agent start ')
					call_gps_agent(zipdest)
					
					reply_infoa=ipinfo+'changed build version and execute'+',zipfile info'+zipextractmsg
					reply_info=reply_infoa+",close G:\\ write permission,"+allowdiskmsg
					msg=bytes(reply_info,'utf-8')
					c_socket.sendto(msg,send_addr)
				elif Statflag==('Upload_Game') and len(game_source) > 4 and len(game_build):
					if shutil.isdir(game_source):
						try:
							shutil.copy(game_source,game_dest)
						except OSError as gamecopyerr:
							errmsg=ipinfo+',Error:'+str(gamecopyerr)
							msg=bytes(errmsg)
							c_socket.sendto(msg,send_addr)
					else:
						msg=bytes('GameSource is wrong')
						c_socket.sendto(msg,send_addr)
				elif Statflag==('start_agernt'):
					print('start agent by remote command')
					#call Agent wake up to work 
					project=project_init+'-'+'assembly-all'
					destdir='G:\\GC\\'+project
					call_gps_agent(destdir)
				elif Statflag==('stop_agent')
					
				else:
					reply_info='you send wrong paramater'
					msg=bytes(reply_info,'utf-8')
					c_socket.sendto(msg,send_addr)
			except (IOError, os.error) as why2:
				print(why2)
	except (KeyboardInterrupt,SystemExit):
		print('finished the program?')
		choice = sys.stdin.readline().rstrip()
		if((choice=='yes') or (choice == 'y')):
			sys.exit(1)
		else:
			raise
addr=''
port=8888		

create_boardcast(addr,port)

	