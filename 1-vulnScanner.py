
#!/usr/bin/python
# -*- coding: utf-8 -*-
import socket #importing socket module
import os     #importing operating system module
import sys    #importing sys module


def retBanner(ip, port): #function to retrive banner
    try:                 # try xy and do z if exception occurs
        socket.setdefaulttimeout(2) #setting default time for new sockets
        s = socket.socket() #creating new variable s from class socket
        s.connect((ip, port)) #network connection to socket
        banner = s.recv(1024) #receiving information from socket
        return banner  #printing the 1024 bytes on socket
    except:  #in case an exception occurs
        return


def checkVulns(banner, filename):

    f = open(filename, 'r') #open file in read only mode
    for line in f.readlines(): #iterate through each line in the file
        if line.strip('\n') in banner: #compare it against our banner
            print '[+] Server is vulnerable: ' +
                banner.strip('\n')
                                    #print if there is a match

def main():

    if len(sys.argv) == 2: #if there are two arguments
        filename = sys.argv[1] #the first argument is the file name
        if not os.path.isfile(filename): #print error, otherwise ^
            print '[-] ' + filename +\
                ' does not exist.'
            exit(0)

        if not os.access(filename, os.R_OK): #print error if no read permissions to file
            print '[-] ' + filename +\
                ' access denied.'
            exit(0)
    else:
        print '[-] Usage: ' + str(sys.argv[0]) +\
            ' <vuln filename>'
        exit(0)

    portList = [21,22,25,80,110,443] #array containing list of ports
    for x in range(147, 150): #range of ip address'
        ip = '192.168.95.' + str(x) #goes through the various IP above
         for port in portList: #goes through the various poarts
            banner = retBanner(ip, port) #checking sockets connected to various ip&port combinations
            if banner: #print banner when you find one
                print '[+] ' + ip + ' : ' + banner
                checkVulns(banner, filename) #compare the banner with file function


if __name__ == '__main__':
    main()
