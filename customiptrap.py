#encoding=utf-8
'''
Created on Jul 24, 2015

@author: xtest
'''
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("scapy.loading").setLevel(logging.ERROR)
from scapy.all import *
from scapy.layers.inet import IP, UDP
from scapy.layers.snmp import SNMP, SNMPtrapv2, SNMPvarbind
#from scapy.asn1.asn1 import ASN1_OID, ASN1_GAUGE32, ASN1_STRING

#from scapy.all import *
import datetime as pydate
import os, sys, time
sys.stdout = open("printout", 'wb')

def getHexNow(nowtime = None):
    hexValue = ''
    hex_new = ''
    directionFromUTC = hoursFromUTC = minutesFromUTC = zone = None
    t = time.time()
    if(time.localtime(t).tm_isdst and time.daylight):
        zone = time.altzone
    else:
        zone = time.timezone
    
    #Direction from UTC
    if zone < 0:
        directionFromUTC = '+'
    else:
        directionFromUTC = '-'    
    
    #Hours and minutes from UTC
    hoursFromUTC = zone / -(60*60)
    minutesFromUTC = -1 * (zone % 60)

    #Get the time of now
    if(nowtime is None):
        nowtime = pydate.datetime.now()
    dt = nowtime
    #Get the year formated
    high, low = divmod(dt.year, 256)
    #hexValue += chr(high)
    hex_new += chr(high)
    if high < 16:
        hexValue += '0'
    hexValue += format(high, 'x')
    hex_new += chr(low)
    if low < 16:
        hexValue += '0'
    hexValue += format(low, 'x')
    
    #Format month
    hex_new += chr(dt.month)
    hexValue += '0' + format(dt.month, 'x')
    
    #Format day
    hex_new += chr(dt.day)
    if dt.day < 16:
        hexValue += '0'
    hexValue += format(dt.day, 'x')   
    
    #Format hour, minute, second
    hex_new += chr(dt.hour)
    if dt.hour < 16:
        hexValue += '0'
    hexValue += format(dt.hour, 'x')

    hex_new += chr(dt.minute)
    if dt.minute < 16:
        hexValue += '0'
    hexValue += format(dt.minute, 'x')
    
    hex_new += chr(dt.second)
    if dt.second < 16:
        hexValue += '0'
    hexValue += format(dt.second, 'x')
    
    #Format the Deli second
    deli_sec = int(round(dt.microsecond / 10000))
    hex_new += chr(deli_sec)
    if(deli_sec < 16):
        hexValue += '0'
    hexValue += format(deli_sec, 'x')
    
    hex_new += hex(ord(directionFromUTC))
    #Direction
    hexValue += format(ord(directionFromUTC), 'x')

    hex_new += chr(hoursFromUTC)
    #Hour from UTC
    hexValue += '0' + format(hoursFromUTC, 'x')

    #Minute from UTC
    hex_new += chr(minutesFromUTC)
    if minutesFromUTC < 16:
        hexValue += '0'
    hexValue += format(minutesFromUTC, 'x')
    return 0, hexValue, hex_new

def getTheCounterValue():
    current_path = os.path.dirname(os.path.realpath(__file__))
    counter_file = os.path.normpath(current_path + os.sep + "alarmid" + os.sep + "alarmid")
    if(not os.path.isfile(counter_file)):
        raise Exception("Cannot find the counter value file!")
    else:
        try:
            f = open(counter_file, 'r+')
            line = f.readline()
            f.close()
            return int(line)
        except Exception as e:
            raise Exception(e.message)

def writeBackCounter(counter):
    current_path = os.path.dirname(os.path.realpath(__file__))
    counter_file = os.path.normpath(current_path + os.sep + "alarmid" + os.sep + "alarmid")
    if(not os.path.isfile(counter_file)):
        raise Exception("Cannot find the counter value file!")
    else:
        try:
            f = open(counter_file, 'w')
            f.write(str(counter))
            f.flush()
            f.close()
        except Exception as e:
            raise Exception(e.message)

if __name__ == '__main__':
    alarmid = getTheCounterValue()
    alarmseverity = 2
    if(len(sys.argv) > 1):
        if(str(sys.argv[1]) == "clear"):
            alarmid -= 1
            alarmseverity = 5
    #writeBackCounter(1200001)
    print IP.__module__
    print UDP.__module__
    print SNMP.__module__
    print SNMPtrapv2.__module__
    print SNMPvarbind.__module__
    print ASN1_OID.__module__
    print ASN1_GAUGE32.__module__
    
    i, s, h = getHexNow()
    i = IP(dst="10.184.74.67", src="150.236.233.45")/UDP(sport=161,dport=162)
    s = SNMP(version=1 , community= 'test' , PDU=SNMPtrapv2(id=14452, 
        varbindlist=[
            SNMPvarbind(oid=ASN1_OID('1.3.6.1.6.3.1.1.4.1.0'),value=ASN1_STRING('1.3.6.1.4.1.193.82.2.0.1')),
            SNMPvarbind(oid=ASN1_OID('1.3.6.1.2.1.1.3.0'),value=ASN1_GAUGE32(0)),
            SNMPvarbind(oid=ASN1_OID('1.3.6.1.4.1.193.82.1.8.1.4.0'),value=ASN1_STRING(h)),
            SNMPvarbind(oid=ASN1_OID('1.3.6.1.4.1.193.82.1.8.1.1.0'),value=ASN1_GAUGE32(alarmid)),
            SNMPvarbind(oid=ASN1_OID('1.3.6.1.4.1.193.82.1.8.1.2.0'),value=ASN1_STRING('li mme [10.185.127.90]:5000')), 
            SNMPvarbind(oid=ASN1_OID('1.3.6.1.4.1.193.82.1.8.1.5.0'),value=ASN1_GAUGE32(2)), 
            SNMPvarbind(oid=ASN1_OID('1.3.6.1.4.1.193.82.1.8.1.6.0'),value=ASN1_GAUGE32(6)), 
            SNMPvarbind(oid=ASN1_OID('1.3.6.1.4.1.193.82.1.8.1.7.0'),value=ASN1_GAUGE32(alarmseverity)), 
            SNMPvarbind(oid=ASN1_OID('1.3.6.1.4.1.193.82.1.8.1.13.0'),value=ASN1_STRING('MME: X2 connection failed. LIC address: [10.185.127.90]:5000. LIC ID: test. Reason: TCP Connection failed.')), 
            SNMPvarbind(oid=ASN1_OID('1.3.6.1.4.1.193.82.1.8.1.8.0'),value=ASN1_STRING('liX2ConnFailureMajor'))]))

    send(i / s)
    writeBackCounter(alarmid + 1)