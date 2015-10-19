#!/usr/bin/python2.7
# Developed by Rostislav Bagrov (bagrov.rostislav@gmail.com)
# >>> ver 0.0.1
# - SSH to mikrotik. Action: Taking arguments from cli: --user, --password, --hostname, --port
# - Create: --ident option. Action: prints router identity - default action
# - Add to: --ident full. Action: prints system architecture
# - Create: --adduser. Action: -adduser user:pass
# - Create: --deluser. Action: -deluser user
# - Add to: --hostname <arg1>,<arg2>,...<argN>
# ----------------------------------------------------------------------------
# >>> ver 0.0.2
# - Create: Certificate connection: ID-DSA
# - Create: --conf. Action: Access from list in xml schema.
# - Create: --listusers. Action: Print list of current users
# - Create: --run. Action: Runs whatever in quotes. '/system identity get name'
# - Create: --health. Action: Returns health information.
# - Fix: clean code, clean usage, make it simpler and faster
# ----------------------------------------------------------------------------
# >>> ver 0.0.3
# - Create: --silent. Action: No output at all
# - Add to: Github
# - Parse rsc file to target device
# - Upload file to target device
#

# ----------------------------------------
# Import modules
import argparse, os, sys, re, time, warnings, paramiko, xml.etree.ElementTree as xmlparser

# ----------------------------------------
# Argparse help arguments
parser = argparse.ArgumentParser(description='Mikrotik control software')
parser.add_argument('--u', dest='user', default='admin', help='SSH user')
parser.add_argument('--pwd', dest='password', default='', help='SSH password')
parser.add_argument('--ip', dest='ip', default='', help='Destination host or IP address. Ex: hostA,hostB')
parser.add_argument('--p', dest='port', default=22, help='Destination ssh port. Ex: 22')
parser.add_argument('--ident', dest='ident', help='Print router identity. Ex: yes/full')
parser.add_argument('--adduser', dest='adduser', default='None', help='Adds user to router. Ex: user:pass')
parser.add_argument('--deluser', dest='deluser', default='None', help='Deletes user from  router. Ex: user')
parser.add_argument('--conf', dest='conf', default='None', help='Full path to XML conf file. Ex: /home/user/conffile.xml')
parser.add_argument('--key', dest='key', action='store_true', help='User default ID-DSA key')
parser.add_argument('--listusers', dest='listusers',action='store_true', help='Lists all users.')
parser.add_argument('--health', dest='health',action='store_true', help='Lists health status.')
parser.add_argument('--run', dest='run', default='None', help='Runs whatever you throu at the target router. Use quotes!')
parser.add_argument('--silent', dest='silent', default='None', help='Does not produce any outout to stdout')
parser.add_argument('--rsc', dest='rsc', default='None', help='Full path to RSC file. Ex: /home/user/address_list.rsc')
parser.add_argument('--put', dest='put', default='None', help='Full path to file. Ex: /home/user/somefile')
argresults = parser.parse_args()

# ----------------------------------------
# define mikrotik commands in variables for easy amend

mkident = ':put [ /system identity get name ]'
mkidentfull = ':put [ /system resource print ]'
dsakeylocation = os.getenv("HOME") + '/.ssh/id_dsa'
userprint = ':put [ /user print ]'
healthcheck = ':put [ /system health print ]'


# ----------------------------------------
# define functions

def _c_put(conf,put):
    if "/" in put:
        putfile = put.split('/')
    xml_conf = _conf_parse(conf)
    for device in xml_conf.findall('device'):
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(hostname=device.find('address').text,port=int(device.find('port').text),username=device.find('user').text,password=device.find('password').text,allow_agent=False,look_for_keys=False)
            ftp = ssh.open_sftp()
            ftp.put(put,str(putfile[-1]))
            ftp.close
            ssh.close
        except Exception as error:
            if argresults.silent == 'None':
                print('Cannot upload ' + rsc + ' file on: ' + device.get('name')  + ' -> ' + device.find('address').text + ' because: ' + str(error))

def _c_rsc(conf,rsc):
    if "/" in rsc:
        rscfile = rsc.split('/')
    xml_conf = _conf_parse(conf)
    importrsc = 'import ' + str(rscfile[-1])
    for device in xml_conf.findall('device'):
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(hostname=device.find('address').text,port=int(device.find('port').text),username=device.find('user').text,password=device.find('password').text,allow_agent=False,look_for_keys=False)
            ftp = ssh.open_sftp()
            ftp.put(rsc,str(rscfile[-1]))
            stdin,stdout,stderr=ssh.exec_command(importrsc)
            ftp.close
            ssh.close
        except Exception as error:
            if argresults.silent == 'None':
                print('Cannot upload ' + rsc + ' file on: ' + device.get('name')  + ' -> ' + device.find('address').text + ' because: ' + str(error))

def _conf_parse(conf):
    try:
        xml_conf = xmlparser.parse(conf)
        return xml_conf
    except IOError as e:
        if argresults.silent == 'None':
            print "I/O error for file: " + cfile + " - {0}".format(e.strerror)

def _userdel(user,hostname,password,port,userforremove,authkey):
    try:
        if "," in hostname:
            hosts = hostname.split(',')
            for host in range(len(hosts)):
                if authkey:
                    ssh = paramiko.SSHClient()
                    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    ssh.connect(hosts[host],port=int(port),username=user,key_filename=dsakeylocation,allow_agent=False,look_for_keys=False)
                    stdin,stdout,stderr=ssh.exec_command(':put [/user find name=' + userforremove + ']')
                    if "*" in stdout.read():
                        stdin,stdout,stderr=ssh.exec_command(':put [/user remove ' + userforremove + ']')
                        stdin,stdout,stderr=ssh.exec_command(':put [/user find name=' + userforremove + ']')
                        if "*" in stdout.read():
                            if argresults.silent == 'None':
                                print('User <' + userforremove + '> on ' + hosts[host] + ' cannot be removed!')
                        else:
                            if argresults.silent == 'None':
                                print('User <' + userforremove + '> on ' + hosts[host] + ' is succesfully removed!')
                    else:
                        if argresults.silent == 'None':
                            print('Cannot add delete user <' + userforremove + '> as the it doesn not exists!')
                    ssh.close
                else:
                    ssh = paramiko.SSHClient()
                    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    ssh.connect(hosts[host],port=int(port),username=user,password=password,allow_agent=False,look_for_keys=False)
                    stdin,stdout,stderr=ssh.exec_command(':put [/user find name=' + userforremove + ']')
                    if "*" in stdout.read():
                        stdin,stdout,stderr=ssh.exec_command(':put [/user remove ' + userforremove + ']')
                        stdin,stdout,stderr=ssh.exec_command(':put [/user find name=' + userforremove + ']')
                        if "*" in stdout.read():
                            if argresults.silent == 'None':
                                print('User <' + userforremove + '> on ' + hosts[host] + ' cannot be removed!')
                        else:
                            if argresults.silent == 'None':
                                print('User <' + userforremove + '> on ' + hosts[host] + ' is succesfully removed!')
                    else:
                        if argresults.silent == 'None':
                            print('Cannot add delete user <' + userforremove + '> as the it doesn not exists!')
                    ssh.close
        else:
            if authkey:
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(hostname,port=int(port),username=user,key_filename=dsakeylocation,allow_agent=False,look_for_keys=False)
                stdin,stdout,stderr=ssh.exec_command(':put [/user find name=' + userforremove + ']')
                if "*" in stdout.read():
                    stdin,stdout,stderr=ssh.exec_command(':put [/user remove ' + userforremove + ']')
                    stdin,stdout,stderr=ssh.exec_command(':put [/user find name=' + userforremove + ']')
                    if "*" in stdout.read():
                        if argresults.silent == 'None':
                            print('User <' + userforremove + '> on ' + hostname + ' cannot be removed!')
                    else:
                        if argresults.silent == 'None':
                            print('User <' + userforremove + '> on ' + hostname + ' is succesfully removed!')
                else:
                    if argresults.silent == 'None':
                        print('Cannot add delete user <' + userforremove + '> as the it doesn not exists!')
                ssh.close
            else:
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(hostname,port=int(port),username=user,password=password,allow_agent=False,look_for_keys=False)
                stdin,stdout,stderr=ssh.exec_command(':put [/user find name=' + userforremove + ']')
                if "*" in stdout.read():
                    stdin,stdout,stderr=ssh.exec_command(':put [/user remove ' + userforremove + ']')
                    stdin,stdout,stderr=ssh.exec_command(':put [/user find name=' + userforremove + ']')
                    if "*" in stdout.read():
                        if argresults.silent == 'None':
                            print('User <' + userforremove + '> on ' + hostname + ' cannot be removed!')
                    else:
                        if argresults.silent == 'None':
                            print('User <' + userforremove + '> on ' + hostname + ' is succesfully removed!')
                else:
                    if argresults.silent == 'None':
                        print('Cannot add delete user <' + userforremove + '> as the it doesn not exists!')
                ssh.close
    except:
        if argresults.silent == 'None':
            print('Cannot remove the user ' + userforremove)

def _c_userdel(conf,userforremove):
    xml_conf = _conf_parse(conf)
    for device in xml_conf.findall('device'):
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(hostname=device.find('address').text,port=int(device.find('port').text),username=device.find('user').text,password=device.find('password').text,allow_agent=False,look_for_keys=False)
            stdin,stdout,stderr=ssh.exec_command(':put [/user find name=' + userforremove + ']')
            if "*" in stdout.read():
                stdin,stdout,stderr=ssh.exec_command(':put [/user remove ' + userforremove + ']')
                stdin,stdout,stderr=ssh.exec_command(':put [/user find name=' + userforremove + ']')
                if "*" in stdout.read():
                    if argresults.silent == 'None':
                        print('User <' + userforremove + '> on ' + device.get('name') + ' cannot be removed!')
                else:
                    if argresults.silent == 'None':
                        print('User <' + userforremove + '> on ' + device.get('name') + ' is succesfully removed!')
            else:
                if argresults.silent == 'None':
                    print('Cannot add delete user <' + userforremove + '> on ' + device.get('name') +  ' as the it doesn not exists!')
            ssh.close
        except Exception as error:
            if argresults.silent == 'None':
                print('Cannot execute Ident command on: ' + device.get('name')  + ' -> ' + device.find('address').text + ' because: ' + str(error))

def _useradd(user,hostname,password,port,usernpass,authkey):
    try:
        if "," in hostname:
            hosts = hostname.split(',')
            for host in range(len(hosts)):
                if authkey:
                    ssh = paramiko.SSHClient()
                    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    login_credentials = usernpass.split(':')
                    ssh.connect(hosts[host],port=int(port),username=user,key_filename=dsakeylocation,allow_agent=False,look_for_keys=False)
                    stdin,stdout,stderr=ssh.exec_command(':put [/user find name=' + login_credentials[0] + ']')
                    if "*" in stdout.read():
                        if argresults.silent == 'None':
                            print('Cannot add new user <' + login_credentials[0] + '> as the it already exists!')
                    else:
                        stdin,stdout,stderr=ssh.exec_command(':put [/user add name=' + login_credentials[0] + ' password=' + login_credentials[1] + ' group=full ]')
                        stdin,stdout,stderr=ssh.exec_command(':put [/user find name=' + login_credentials[0] + ']')
                    if "*" in stdout.read():
                        if argresults.silent == 'None':
                            print('User <' + login_credentials[0] + '> on ' + hosts[host] + ' is succesfully created!')
                    else:
                        if argresults.silent == 'None':
                            print('User <' + login_credentials[0] + '> on ' + hosts[host] + ' failed to be created!')
                    ssh.close
                else:
                    ssh = paramiko.SSHClient()
                    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    login_credentials = usernpass.split(':')
                    ssh.connect(hosts[host],port=int(port),username=user,password=password,allow_agent=False,look_for_keys=False)
                    stdin,stdout,stderr=ssh.exec_command(':put [/user find name=' + login_credentials[0] + ']')
                    if "*" in stdout.read():
                        if argresults.silent == 'None':
                            print('Cannot add new user <' + login_credentials[0] + '> as the it already exists!')
                    else:
                        stdin,stdout,stderr=ssh.exec_command(':put [/user add name=' + login_credentials[0] + ' password=' + login_credentials[1] + ' group=full ]')
                        stdin,stdout,stderr=ssh.exec_command(':put [/user find name=' + login_credentials[0] + ']')
                    if "*" in stdout.read():
                        if argresults.silent == 'None':
                            print('User <' + login_credentials[0] + '> on ' + hosts[host] + ' is succesfully created!')
                    else:
                        if argresults.silent == 'None':
                            print('User <' + login_credentials[0] + '> on ' + hosts[host] + ' failed to be created!')
                    ssh.close
        else:
            if authkey:
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                login_credentials = usernpass.split(':')
                ssh.connect(hostname,port=int(port),username=user,key_filename=dsakeylocation,allow_agent=False,look_for_keys=False)
                stdin,stdout,stderr=ssh.exec_command(':put [/user find name=' + login_credentials[0] + ']')
                if "*" in stdout.read():
                    if argresults.silent == 'None':
                        print('Cannot add new user <' + login_credentials[0] + '> as the it already exists!')
                else:
                    stdin,stdout,stderr=ssh.exec_command(':put [/user add name=' + login_credentials[0] + ' password=' + login_credentials[1] + ' group=full ]')
                    stdin,stdout,stderr=ssh.exec_command(':put [/user find name=' + login_credentials[0] + ']')
                if "*" in stdout.read():
                    if argresults.silent == 'None':
                        print('User <' + login_credentials[0] + '> on ' + hostname + ' is succesfully created!')
                else:
                    if argresults.silent == 'None':
                        print('User <' + login_credentials[0] + '> on ' + hostname + ' failed to be created!')
                ssh.close
            else:
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                login_credentials = usernpass.split(':')
                ssh.connect(hostname,port=int(port),username=user,password=password,allow_agent=False,look_for_keys=False)
                stdin,stdout,stderr=ssh.exec_command(':put [/user find name=' + login_credentials[0] + ']')
                if "*" in stdout.read():
                    if argresults.silent == 'None':
                        print('Cannot add new user <' + login_credentials[0] + '> as the it already exists!')
                else:
                    stdin,stdout,stderr=ssh.exec_command(':put [/user add name=' + login_credentials[0] + ' password=' + login_credentials[1] + ' group=full ]')
                    stdin,stdout,stderr=ssh.exec_command(':put [/user find name=' + login_credentials[0] + ']')
                if "*" in stdout.read():
                    if argresults.silent == 'None':
                        print('User <' + login_credentials[0] + '> on ' + hostname + ' is succesfully created!')
                else:
                    if argresults.silent == 'None':
                        print('User <' + login_credentials[0] + '> on ' + hostname + ' failed to be created!')
                ssh.close
    except Exception as error:
        if argresults.silent == 'None':
            print('Cannot add the user ' + login_credentials[0])
            print(error)

def _c_useradd(conf,usernpass):
    xml_conf = _conf_parse(conf)
    for device in xml_conf.findall('device'):
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            login_credentials = usernpass.split(':')
            ssh.connect(hostname=device.find('address').text,port=int(device.find('port').text),username=device.find('user').text,password=device.find('password').text,allow_agent=False,look_for_keys=False)
            stdin,stdout,stderr=ssh.exec_command(':put [/user find name=' + login_credentials[0] + ']')
            if "*" in stdout.read():
                if argresults.silent == 'None':
                    print('Cannot add new user <' + login_credentials[0] + '> as the it already exists!')
            else:
                stdin,stdout,stderr=ssh.exec_command(':put [/user add name=' + login_credentials[0] + ' password=' + login_credentials[1] + ' group=full ]')
                stdin,stdout,stderr=ssh.exec_command(':put [/user find name=' + login_credentials[0] + ']')
            if "*" in stdout.read():
                if argresults.silent == 'None':
                    print('User <' + login_credentials[0] + '> on ' + device.get('name') + ' is succesfully created!')
            else:
                if argresults.silent == 'None':
                    print('User <' + login_credentials[0] + '> on ' + device.get('name') + ' failed to be created!')
            ssh.close
        except Exception as error:
            if argresults.silent == 'None':
                print('Cannot execute Ident command on: ' + device.get('name')  + ' -> ' + device.find('address').text + ' because: ' + str(error))

def _ident(user,hostname,password,port,authkey):
    try:
        if "," in hostname:
            hosts = hostname.split(',')
            for host in range(len(hosts)):
                if authkey:
                    ssh = paramiko.SSHClient()
                    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    ssh.connect(hosts[host],port=int(port),username=user,key_filename=dsakeylocation,allow_agent=False,look_for_keys=False)
                    stdin,stdout,stderr=ssh.exec_command(mkident)
                    ssh.close
                else:
                    ssh = paramiko.SSHClient()
                    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    ssh.connect(hosts[host],port=int(port),username=user,password=password,allow_agent=False,look_for_keys=False)
                    stdin,stdout,stderr=ssh.exec_command(mkident)
                    ssh.close
                if argresults.silent == 'None':
                    print 'For ' + hosts[host] + ' identity is: ', stdout.read()

        else:
            if authkey:
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(hostname,port=int(port),username=user,key_filename=dsakeylocation,allow_agent=False,look_for_keys=False)
                stdin,stdout,stderr=ssh.exec_command(mkident)
                if argresults.silent == 'None':
                    print 'For ' + hostname + ' identity is: ', stdout.read()
                ssh.close
            else:
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(hostname,port=int(port),username=user,password=password,allow_agent=False,look_for_keys=False)
                stdin,stdout,stderr=ssh.exec_command(mkident)
                if argresults.silent == 'None':
                    print 'For ' + hostname + ' identity is: ', stdout.read()
                ssh.close
    except Exception as error:
        if argresults.silent == 'None':
            print('Cannot execute Ident command on: ' + hostname)
            print(error)

def _c_ident(conf):
    xml_conf = _conf_parse(conf)
    for device in xml_conf.findall('device'):
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(hostname=device.find('address').text,port=int(device.find('port').text),username=device.find('user').text,password=device.find('password').text,allow_agent=False,look_for_keys=False)
            stdin,stdout,stderr=ssh.exec_command(mkident)
            ssh.close
            if argresults.silent == 'None':
                print 'For ' + device.get('name') + ' identity is: ', stdout.read()
        except Exception as error:
            if argresults.silent == 'None':
                print('Cannot execute Ident command on: ' + device.get('name')  + ' -> ' + device.find('address').text + ' because: ' + str(error))

def _identfull(user,hostname,password,port,authkey):
    try:
        if "," in hostname:
            hosts = hostname.split(',')
            for host in range(len(hosts)):
                if authkey:
                    ssh = paramiko.SSHClient()
                    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    ssh.connect(hosts[host],port=int(port),username=user,key_filename=dsakeylocation,allow_agent=False,look_for_keys=False)
                    stdin,stdout,stderr=ssh.exec_command(mkident)
                    if argresults.silent == 'None':
                        print 'For ' + hosts[host] + ' identity is: ', stdout.read()
                    stdin,stdout,stderr=ssh.exec_command(mkidentfull)
                    if argresults.silent == 'None':
                        print 'Resource data for ' + hosts[host] + ' is: \n', stdout.read()
                    ssh.close
                else:
                    ssh = paramiko.SSHClient()
                    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    ssh.connect(hosts[host],port=int(port),username=user,password=password,allow_agent=False,look_for_keys=False)
                    stdin,stdout,stderr=ssh.exec_command(mkident)
                    if argresults.silent == 'None':
                        print 'For ' + hosts[host] + ' identity is: ', stdout.read()
                    stdin,stdout,stderr=ssh.exec_command(mkidentfull)
                    if argresults.silent == 'None':
                        print 'Resource data for ' + hosts[host] + ' is: \n', stdout.read()
                    ssh.close
        else:
            if authkey:
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(hostname,port=int(port),username=user,key_filename=dsakeylocation,allow_agent=False,look_for_keys=False)
                stdin,stdout,stderr=ssh.exec_command(mkident)
                if argresults.silent == 'None':
                    print 'For ' + hostname + ' identity is: ', stdout.read()
                stdin,stdout,stderr=ssh.exec_command(mkidentfull)
                if argresults.silent == 'None':
                    print 'Resource data for ' + hostname + ' is: \n', stdout.read()
                ssh.close
            else:
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(hostname,port=int(port),username=user,password=password,allow_agent=False,look_for_keys=False)
                stdin,stdout,stderr=ssh.exec_command(mkident)
                if argresults.silent == 'None':
                    print 'For ' + hostname + ' identity is: ', stdout.read()
                stdin,stdout,stderr=ssh.exec_command(mkidentfull)
                if argresults.silent == 'None':
                    print 'Resource data for ' + hostname + ' is: \n', stdout.read()
                ssh.close
    except:
        if argresults.silent == 'None':
            print('Cannot execute Ident Full command on: ' + hostname)

def _c_identfull(conf):
    xml_conf = _conf_parse(conf)
    for device in xml_conf.findall('device'):
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(hostname=device.find('address').text,port=int(device.find('port').text),username=device.find('user').text,password=device.find('password').text,allow_agent=False,look_for_keys=False)
            stdin,stdout,stderr=ssh.exec_command(mkident)
            if argresults.silent == 'None':
                print 'For ' + device.get('name') + ' identity is: ', stdout.read()
            stdin,stdout,stderr=ssh.exec_command(mkidentfull)
            if argresults.silent == 'None':
                print 'Resource data for ' + device.get('name') + ' is: \n', stdout.read()
            ssh.close
        except Exception as error:
            if argresults.silent == 'None':
                print('Cannot execute Ident command on: ' + device.get('name')  + ' -> ' + device.find('address').text + ' because: ' + str(error))

def _listusers(user,hostname,password,port,authkey):
    try:
        if "," in hostname:
            hosts = hostname.split(',')
            for host in range(len(hosts)):
                if authkey:
                    ssh = paramiko.SSHClient()
                    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    ssh.connect(hosts[host],port=int(port),username=user,key_filename=dsakeylocation,allow_agent=False,look_for_keys=False)
                    stdin,stdout,stderr=ssh.exec_command(mkident)
                    if argresults.silent == 'None':
                        print 'For: ' + hosts[host] + ' and identity: ', stdout.read() , 'User list is: '
                    stdin,stdout,stderr=ssh.exec_command(userprint)
                    if argresults.silent == 'None':
                        print stdout.read()
                    ssh.close
                else:
                    ssh = paramiko.SSHClient()
                    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    ssh.connect(hosts[host],port=int(port),username=user,password=password,allow_agent=False,look_for_keys=False)
                    stdin,stdout,stderr=ssh.exec_command(mkident)
                    if argresults.silent == 'None':
                        print 'For: ' + hosts[host] + ' and identity: ', stdout.read() , 'User list is: '
                    stdin,stdout,stderr=ssh.exec_command(userprint)
                    if argresults.silent == 'None':
                        print stdout.read()
                    ssh.close
        else:
            if authkey:
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(hostname,port=int(port),username=user,key_filename=dsakeylocation,allow_agent=False,look_for_keys=False)
                stdin,stdout,stderr=ssh.exec_command(mkident)
                if argresults.silent == 'None':
                    print 'For: ' + hostname + ' and identity: ', stdout.read() , 'User list is: '
                stdin,stdout,stderr=ssh.exec_command(userprint)
                if argresults.silent == 'None':
                    print stdout.read()
                ssh.close
            else:
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(hostname,port=int(port),username=user,password=password,allow_agent=False,look_for_keys=False)
                stdin,stdout,stderr=ssh.exec_command(mkident)
                if argresults.silent == 'None':
                    print 'For: ' + hostname + ' and identity: ', stdout.read() , 'User list is: '
                stdin,stdout,stderr=ssh.exec_command(userprint)
                if argresults.silent == 'None':
                    print stdout.read()
                ssh.close
    except Exception as error:
        if argresults.silent == 'None':
            print('Cannot list users on: ' + hostname)
            print(error)

def _c_listusers(conf):
    xml_conf = _conf_parse(conf)
    for device in xml_conf.findall('device'):
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(hostname=device.find('address').text,port=int(device.find('port').text),username=device.find('user').text,password=device.find('password').text,allow_agent=False,look_for_keys=False)
            stdin,stdout,stderr=ssh.exec_command(mkident)
            if argresults.silent == 'None':
                print 'For: ' + device.get('name') + ' and identity: ', stdout.read() , 'User list is: '
            stdin,stdout,stderr=ssh.exec_command(userprint)
            if argresults.silent == 'None':
                print stdout.read()
            ssh.close
        except Exception as error:
            if argresults.silent == 'None':
                print('Cannot execute Ident command on: ' + device.get('name')  + ' -> ' + device.find('address').text + ' because: ' + str(error))

def _health(user,hostname,password,port,authkey):
    try:
        if "," in hostname:
            hosts = hostname.split(',')
            for host in range(len(hosts)):
                if authkey:
                    ssh = paramiko.SSHClient()
                    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    ssh.connect(hosts[host],port=int(port),username=user,key_filename=dsakeylocation,allow_agent=False,look_for_keys=False)
                    stdin,stdout,stderr=ssh.exec_command(mkident)
                    if argresults.silent == 'None':
                        print 'For: ' + hosts[host] + ' and identity: ', stdout.read() , 'Health status is: '
                    stdin,stdout,stderr=ssh.exec_command(healthcheck)
                    if argresults.silent == 'None':
                        print stdout.read()
                    ssh.close
                else:
                    ssh = paramiko.SSHClient()
                    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    ssh.connect(hosts[host],port=int(port),username=user,password=password,allow_agent=False,look_for_keys=False)
                    stdin,stdout,stderr=ssh.exec_command(mkident)
                    if argresults.silent == 'None':
                        print 'For: ' + hosts[host] + ' and identity: ', stdout.read() , 'Health status is: '
                    stdin,stdout,stderr=ssh.exec_command(healthcheck)
                    if argresults.silent == 'None':
                        print stdout.read()
                    ssh.close
        else:
            if authkey:
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(hostname,port=int(port),username=user,key_filename=dsakeylocation,allow_agent=False,look_for_keys=False)
                stdin,stdout,stderr=ssh.exec_command(mkident)
                if argresults.silent == 'None':
                    print 'For: ' + hostname + ' and identity: ', stdout.read() , 'Health status is: '
                stdin,stdout,stderr=ssh.exec_command(healthcheck)
                if argresults.silent == 'None':
                    print stdout.read()
                ssh.close
            else:
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(hostname,port=int(port),username=user,password=password,allow_agent=False,look_for_keys=False)
                stdin,stdout,stderr=ssh.exec_command(mkident)
                if argresults.silent == 'None':
                    print 'For: ' + hostname + ' and identity: ', stdout.read() , 'Health status is: '
                stdin,stdout,stderr=ssh.exec_command(healthcheck)
                if argresults.silent == 'None':
                    print stdout.read()
                ssh.close
    except Exception as error:
        if argresults.silent == 'None':
            print('Cannot print health on: ' + hostname)
            print(error)

def _c_health(conf):
    xml_conf = _conf_parse(conf)
    for device in xml_conf.findall('device'):
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(hostname=device.find('address').text,port=int(device.find('port').text),username=device.find('user').text,password=device.find('password').text,allow_agent=False,look_for_keys=False)
            stdin,stdout,stderr=ssh.exec_command(mkident)
            if argresults.silent == 'None':
                print 'For: ' + device.get('name') + ' and identity: ', stdout.read() , 'Health status is: '
            stdin,stdout,stderr=ssh.exec_command(healthcheck)
            if argresults.silent == 'None':
                print stdout.read()
            ssh.close
        except Exception as error:
            if argresults.silent == 'None':
                print('Cannot execute Ident command on: ' + device.get('name')  + ' -> ' + device.find('address').text + ' because: ' + str(error))

def _run(user,hostname,password,port,runcommand,authkey):
    try:
        if "," in hostname:
            hosts = hostname.split(',')
            for host in range(len(hosts)):
                if authkey:
                    ssh = paramiko.SSHClient()
                    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    ssh.connect(hosts[host],port=int(port),username=user,key_filename=dsakeylocation,allow_agent=False,look_for_keys=False)
                    stdin,stdout,stderr=ssh.exec_command(runcommand)
                    if argresults.silent == 'None':
                        print stdout.read()
                    ssh.close
                else:
                    ssh = paramiko.SSHClient()
                    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    ssh.connect(hosts[host],port=int(port),username=user,password=password,allow_agent=False,look_for_keys=False)
                    stdin,stdout,stderr=ssh.exec_command(runcommand)
                    if argresults.silent == 'None':
                        print stdout.read()
                    ssh.close
        else:
            if authkey:
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(hostname,port=int(port),username=user,key_filename=dsakeylocation,allow_agent=False,look_for_keys=False)
                stdin,stdout,stderr=ssh.exec_command(runcommand)
                if argresults.silent == 'None':
                    print stdout.read()
                ssh.close
            else:
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(hostname,port=int(port),username=user,password=password,allow_agent=False,look_for_keys=False)
                stdin,stdout,stderr=ssh.exec_command(runcommand)
                if argresults.silent == 'None':
                    print stdout.read()
                ssh.close
    except Exception as error:
        if argresults.silent == 'None':
            print('Cannot execute: ', runcommand + ' on ' + hostname)
            print(error)

def _c_run(conf,runcommand):
    xml_conf = _conf_parse(conf)
    for device in xml_conf.findall('device'):
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(hostname=device.find('address').text,port=int(device.find('port').text),username=device.find('user').text,password=device.find('password').text,allow_agent=False,look_for_keys=False)
            stdin,stdout,stderr=ssh.exec_command(runcommand)
            if argresults.silent == 'None':
                print stdout.read()
            ssh.close
        except Exception as error:
            if argresults.silent == 'None':
                print('Cannot execute Ident command on: ' + device.get('name')  + ' -> ' + device.find('address').text + ' because: ' + str(error))

def _dest_check(user,conf,password,ip):

    if user == '' and conf == 'None':
        if argresults.silent == 'None':
            print('No user is entered. Please enter connection username')
    elif password == '' and conf == 'None':
        argresults.key = False
        return argresults.key
    elif ip == '' and conf == 'None':
        if argresults.silent == 'None':
            print('No router IP or hostname is entered.')

def main():

    if argresults.conf != 'None' and argresults.ident == 'yes':
        _c_ident(argresults.conf)
    elif argresults.conf != 'None' and argresults.ident == 'full':
        _c_identfull(argresults.conf)
    elif argresults.conf != 'None' and argresults.listusers is True:
        _c_listusers(argresults.conf)
    elif argresults.conf != 'None' and argresults.health is True:
        _c_health(argresults.conf)
    elif argresults.conf != 'None' and argresults.run != 'None':
        _c_run(argresults.conf,argresults.run)
    elif argresults.conf != 'None' and argresults.adduser != 'None':
        _c_useradd(argresults.conf,argresults.adduser)
    elif argresults.conf != 'None' and argresults.deluser != 'None':
        _c_userdel(argresults.conf,argresults.deluser)
    elif argresults.conf != 'None' and argresults.rsc != 'None':
        _c_rsc(argresults.conf,argresults.rsc)
    elif argresults.conf != 'None' and argresults.put != 'None':
        _c_put(argresults.conf,argresults.put)
    elif argresults.ident == 'yes':
        _dest_check(argresults.user,argresults.conf,argresults.password,argresults.ip)
        _ident(argresults.user,argresults.ip,argresults.password,argresults.port,argresults.key)
    elif argresults.ident == 'full':
        _dest_check(argresults.user,argresults.conf,argresults.password,argresults.ip)
        _identfull(argresults.user,argresults.ip,argresults.password,argresults.port,argresults.key)
    elif argresults.adduser != 'None':
        _dest_check(argresults.user,argresults.conf,argresults.password,argresults.ip)
        _useradd(argresults.user,argresults.ip,argresults.password,argresults.port,argresults.adduser,argresults.key)
    elif argresults.deluser != 'None':
        _dest_check(argresults.user,argresults.conf,argresults.password,argresults.ip)
        _userdel(argresults.user,argresults.ip,argresults.password,argresults.port,argresults.deluser,argresults.key)
    elif argresults.listusers is True:
        _dest_check(argresults.user,argresults.conf,argresults.password,argresults.ip)
        _listusers(argresults.user,argresults.ip,argresults.password,argresults.port,argresults.key)
    elif argresults.health is True:
        _dest_check(argresults.user,argresults.conf,argresults.password,argresults.ip)
        _health(argresults.user,argresults.ip,argresults.password,argresults.port,argresults.key)
    elif argresults.run != 'None':
        _dest_check(argresults.user,argresults.conf,argresults.password,argresults.ip)
        _run(argresults.user,argresults.ip,argresults.password,argresults.port,argresults.run,argresults.key)
    else:
        if argresults.silent == 'None':
            parser.print_usage()

if __name__ == "__main__":
    main()
