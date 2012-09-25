#! /usr/bin/python
# Returns:
# 0: success
# 1: generic error
# 5: service up, no flag  (not used for 'store')
# 9: garbled output
# 13: network
from quickhttp import *
import sys
import re
import os

def store(ip,id,flag):
    url_up = "http://"+ip+"/index.php?p=new_account.php"
    data = {
        "create_account":"",
        "username":id, 
        "password":flag,
        "email":flag,
        "gender":"0",
    }

    try:
        r = req(url_up, data=data)
        s = r.data 
        p = re.compile("Successfully created user acount. Now log in.")

        if p.search(s) is not None:
            print "Flag stored !!!"
            return 0
        else:
            print "Web page not found....!"
            return 9

    except Exception, e:
        print "Network down !!"
        print 13


def retrieve(ip,id,flag):
    url_up = "http://"+ip+"/index.php"

    data = {
        "login":"", 
        "user":id, 
        "password":flag,
    }

    try:
        r = req(url_up, data=data)
        s = r.data
        headers = r.headers
        p = re.compile(id)
        u = re.compile("You are logged in. Now start socializing.")
        
        if p.search(s) is not None and u.search(s) is not None:
            post_url = "http://"+ ip +"/?p=posts.php"
            post_data = os.urandom(16).encode('hex')
            post = {
                "post":"",
                "post":post_data[:-1],
                "Submit":"Post",
            }

            r = req(post_url, data=post, headers=headers, cookie=headers['set-cookie'].split(';')[0])
            s = r.data

            m = re.compile(post_data[:-1])
    
            if m.search(s) is not None:
                print "Yaaa, got back the flag"
                return 0
            else:
                print "Wrong flag!!!"
                return 9
        else:
            print "Service down"
            return 9

    except Exception, e:
        print e
        return 13

	
##
 # Main
##
def main():

        if len(sys.argv) < 5:
                print ("Usage: " + sys.argv[0] + " $action $ip $id $flag")
		print "Internal gameserver script error"
                return 1

        action = sys.argv[1]
        ip = sys.argv[2]
        id = sys.argv[3]
        flag = sys.argv[4]

        if (action == "store"):
                return store(ip,id,flag)
        elif (action == "retrieve"):
                return retrieve(ip,id,flag)
        else:
                print "$action has to be 'store' or 'retrieve'"
		print "Internal gameserver script error"
                return 1

sys.exit(main())
