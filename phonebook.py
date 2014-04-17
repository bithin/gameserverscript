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
import random
import hashlib

def store(ip,id,flag):
    register_url = "http://"+ip+":8880/register"
    data = {
        "username":id, 
        "password":hashlib.md5(flag).hexdigest(),
    }
    
    try:
        register_request = req(register_url, data=data)
        register_data = register_request.data
        check_registration = re.compile("You have successfully register")
        if check_registration.search(register_data) is not None:
            login_url = "http://"+ip+":8880/"
            
            try:
                ping_request = req(login_url)
                cookie = ping_request.headers['set-cookie'].split(';')[0]
                data = {
                    "username":id,
                    "password":hashlib.md5(flag).hexdigest(),
                }
                login_request = req(login_url, data=data, cookie=cookie)
                addcontact_url = "http://"+ip+":8880/addcontact"
                data = {
                    "name":id,
                    "phone":random.randrange(1000000000,9999999999,3),
                    "email":flag,
                }
                
                try:
                    send_contact_details = req(addcontact_url, data=data, cookie=cookie)
                    contact_details = send_contact_details.data
                    flag_data = re.compile("Successfully added")
                    if flag_data.search(contact_details) is not None:
                        print "Flag stored !!!"
                        visit_url = "http://"+ip+":8880/form"
                        visit_home = req(visit_url, cookie=cookie)
                        return 0
                    else:
                        print "Web page not found !"
                        return 9
                except Exception, e:
                    print "Network down !!!"
                    return 13
            except Exception, e:
                print "Network down !!!"
                return 13
        else:
            print "Web page not found....!"
            return 9

    except Exception, e:
        print "Network down !!!"
        return 13


def retrieve(ip,id,flag):
    
    login_url = "http://"+ip+":8880/"
    ping_request = req(login_url)
    cookie = ping_request.headers['set-cookie'].split(';')[0]
    data = {
        "username":id,
        "password":hashlib.md5(flag).hexdigest(),
    }
    login_request = req(login_url, data=data, cookie=cookie)
    flag_data = re.compile(flag)
    if flag_data.search(login_request.data) is not None:
	    print "Ya got back the flag !!!"
	    return 0
    else:
        print "Wrong flag !!"
        return 9
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
