#!/usr/bin/env python
# -*- coding: utf-8 -*- 

#Interface to cjdroute.conf for adding, removing and listing peers and peering information


import json
import re
import random
import string
import argparse
import sys


def json_cleanse(conffile):
    comment_re = re.compile(
        '(^)?[^\S\n]*/(?:\*(.*?)\*/[^\S\n]*|/[^\n]*)($)?',
        re.DOTALL | re.MULTILINE
    )

    with conffile as f:
        content = ''.join(f.readlines())
        #Check comments
        match = comment_re.search(content)
        while match:
            content = content[:match.start()] + content[match.end():]
            match = comment_re.search(content)

    return json.loads(content)


class cjdroute:
    def __init__(self, conffile):
        try:
            self.conffile = conffile
            f = open(conffile, 'rw')
            self.j = json_cleanse(f)
            f.close()
        except:
            print "Unable to open configuration file: " + conffile
            sys.exit()


    ''' Remove all users matching user'''
    def user_del(self, user):
        for key, item in reversed(list(enumerate(self.j['authorizedPasswords']))):
            #print item
            try:
                if item['user'] is user:
                    del self.j['authorizedPasswords'][key]
                    print "Removing user: " + user + " with password: " + item['password']
            except KeyError:
                print 'No username for this password'
        #print json.dumps(self.j['authorizedPasswords'], sort_keys=True, indent=2)

    ''' Add a new user.  Generate random password if password is not supplied'''
    def user_add(self, user, password=0):
        PASSWORD_LENGTH = 22
        if not password:
            password = ''.join(random.choice(string.ascii_letters + string.digits + '_') for x in range(PASSWORD_LENGTH))
        self.j['authorizedPasswords'].append({"user": user, "password": password})
        print "Added user: " + user + " with password: " + password
        #print json.dumps(self.j['authorizedPasswords'], sort_keys=True, indent=2)

    def user_print_all(self):
        print json.dumps(self.j['authorizedPasswords'], sort_keys=True, indent=2)

    def user_print(self, user):
        for key, item in reversed(list(enumerate(self.j['authorizedPasswords']))):
            try:
                if item['user'] is user:
                    print "User " + item['user'] + " exists with password: " + item['password']
            except KeyError:
                    print "Found a user without a username with password: " + item['password']

    ''' Add a connection '''
    def con_add(self, name, ip, port, password, publicKey, trust=9000, authType=1):
        #print json.dumps(self.j['interfaces']['UDPInterface'][0], sort_keys=True, indent=2)
        self.j['interfaces']['UDPInterface'][0]['connectTo'][ip + ":" + port] = {
            "name": name,
            "password": password,
            "authType": authType,
            "trust": trust
        }

        print "Added connection: " + name

    ''' Remove a connection via name '''
    def con_del(self, name):
        for key, item in reversed(list(enumerate(self.j['interfaces']['UDPInterface'][0]['connectTo']))):
            #print item
            try:
                if item['name'] is name:
                    del self.j['interfaces']['UDPInterface'][0]['connectTo'][key]
                    print "Removing connection: " + name
            except KeyError:
                print 'No connection name for this connection'

    ''' Update a connection's value by type '''
    def con_update(self, name, typex, valuex):
        #if typex in ['name', 'password', 'publicKey', 'trust', 'authType']:
        for key, item in self.j['interfaces']['UDPInterface'][0]['connectTo'].iteritems():
            try:
                if name is item['name']:
                    if typex in ['ip', 'port']:
                        print item
                        ip, port = key.split(':')
                        print ip, port
                        if typex is 'ip':
                            conKey = valuex + ":" + port
                        else:
                            conKey = ip + ":" + valuex
                        temphold = item
                        self.j['interfaces']['UDPInterface'][0]['connectTo'].pop(key)
                        self.j['interfaces']['UDPInterface'][0]['connectTo'][conKey] = temphold
                    elif typex in ['name', 'password', 'publicKey', 'trust', 'authType']:
                        item[typex] = valuex
            except KeyError:
                print "KEYERROR"

    ''' Pretty print all connections '''
    def con_print_all(self):
        print json.dumps(self.j['interfaces']['UDPInterface'][0]['connectTo'], sort_keys=True, indent=2)

    ''' Write configuration to file '''
    def write(self, conffile=0):
        if not conffile:
            conffile = self.conffile
        f = open(conffile, 'rw')
        try:
            f.write(json.dumps(self.j))
            f.close()
            print "Successfully updated configuration file: " + conffile
        except:
            print "Unable to update configuration file: " + conffile


''' Command Line Interface (argparse) '''

#TODO Could use some help cleaning this up.  I'm no argparse ninja
parser = argparse.ArgumentParser(description='Manage cjdns configuration.')
#Configuration File
parser.add_argument('--conf', help="Your configuration file", required=True)
#User functionality
parser.add_argument('--useradd', help="Add a user.  Use --username [and --password]", action='store_true')
parser.add_argument('--userdel', help="Remove a user.  Use --username to select which user to remove.", action='store_true')
parser.add_argument('--username', help="Sets username of user to be added with --useradd\nSelects user to be deleted with ---userdel")
parser.add_argument('--password', help="Sets password of user to be added with --useradd", default=0)
#Connection functionality
parser.add_argument('--connectionadd', help="Add a connection.  --connectionadd name,ip,port,pass,pubkey,trust,authtype")
parser.add_argument('--connectiondel', help="Remove a connection.  --connectiondel name")
parser.add_argument('--connectionmod', help="Modify a connection.  --connectionmod name,type,value")


args = vars(parser.parse_args())
try:
    conf = cjdroute(args['conf'])

    if args.get('useradd', None) or args.get('userdel', None):
        if not args.get('username', None):
            print "You must supply a username via --username USERNAME"
            sys.exit()
        else:
            if args.get('useradd', None):
                conf.user_add(args['username'], args['password'])
            elif args.get('userdel', None):
                conf.user_del(args['username'])

    if args.get('connectionadd') or args.get('connectiondel') or args.get('connectionmod'):
        if args.get('connectionadd'):
            #TODO Make trust and authType optional
            try:
                name, ip, port, password, pubkey, trust, authtype = args['connectionadd'].split(',')
                conf.con_add(name, ip, port, password, pubkey, trust, authtype)
            except KeyError:
                print "You must supply name,ip,port,pass,pubkey,trust,authtype"
                sys.exit()
        elif args.get('connectiondel'):
            conf.con_del(args['connectiondel'])
        elif args.get('connectionmod'):
            try:
                name, typex, valuex = args['connectionmod'].split(',')
                conf.con_update(name, typex, valuex)
            except KeyError:
                print "You must supply name,type,value"
                sys.exit()

except KeyError as e:
    print "OHNOESTEHKEYZ!"
    print e



#conf = cjdroute("./cjdroute.conf")
#conf.user_add('USER', "PASS")
#conf.user_print('USER')
#conf.user_add('USER')
#conf.user_print('USER')
#conf.user_del('USER')
#conf.con_add('meLon', '127.0.0.0.1', '9093', 'PASS', 'PUBKEY', trust=9000, authType=1)
#conf.con_print_all()
#conf.con_update('meLon', 'trust', '1')
#conf.con_update('meLon', 'ip', '10.1.1.1')
#conf.con_print_all()
