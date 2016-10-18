#!/usr/bin/python
# -*- coding: iso-8859-15 -
import sys
from subprocess import Popen, PIPE
from config_parser import getKnownIps
from tools import execute
from config_parser import getLsofCommand
import socket
import pwd
import myexceptions
import validations
import re


class Connection:
  local_hostname = ""
  foreign_hostname = ""
  local_service = ""
  foreign_service = ""
  local_ip = ""
  foreign_ip = ""
  local_port = ""
  foreign_port = ""
  state = ""
  user = ""
  process_name = ""

def getConnections(config_file):
  connections = []
  command = "netstat --inet -n -e"
  execution = Popen(command, shell=True, stdout=PIPE, stderr=PIPE)
  for line in execution.stdout.readlines():
    first_word = line.split()[0].strip()
    if first_word == 'tcp' or first_word == 'udp':
      c = Connection()
      data = line.split()
      protocol = first_word
      local_address = data[3].strip()
      foreign_address = data[4].strip()
      c.local_ip, c.local_port = local_address.split(':')
      c.foreign_ip, c.foreign_port = foreign_address.split(':')
      c.state = data[5].strip()
      c.user = pwd.getpwuid(int(data[6].strip()))[0]
      try:
        c.local_hostname = socket.gethostbyaddr(c.local_ip)[0]
      except socket.error:
        c.local_hostname = c.local_ip
      
      try:
        c.foreign_hostname = socket.gethostbyaddr(c.foreign_ip)[0]
      except socket.error:
        c.foreign_hostname = c.foreign_ip
      
      try:
        c.local_service = socket.getservbyport(int(c.local_port), protocol)
      except socket.error:      
        c.local_service = c.local_port  
      
      try:
        c.foreign_service = socket.getservbyport(int(c.foreign_port), protocol)
      except socket.error:
        c.foreign_service = c.foreign_port  
      
      lsof_command = getLsofCommand(config_file)
      output = execute(lsof_command + " | grep " + c.local_port)
      try:
        c.process_name = output[0].split()[0]
      except IndexError:
        c.process_name = "Unknown"
      connections.append(c)  
  return connections

def field_accepted(ip_field, iprange_field):
  if not ip_field.isdigit():
    raise myexceptions.BadIPFormatError, "[Error] All ip fields should be integers"
  if not re.match(r'^(\d{1,3}(,\d{1,3})*|\d{1,3}-\d{1,3}|[*])$', iprange_field):
    raise myexceptions.BadIPFormatError, "[Error] Bad iprange field syntax"
 
  if ip_field == iprange_field:
    return True
  
  if iprange_field == '*':
    return True
  
  if '-' in iprange_field:
    bottom, top = iprange_field.split('-')
    
    if int(ip_field) >= int(bottom) and int(ip_field) <= int(top):
      return True

  if ',' in iprange_field:
    iprange_fields = iprange_field.split(',')
    if ip_field in iprange_fields:
      return True

  return False
   
def recognize(ip, known_ips):
  if not validations.validateIP(ip):
    raise myexceptions.BadIPFormatError, "[Error] Bad IP Format"
  ip_fields = ip.split('.')
  for iprange in known_ips:
    iprange_fields = iprange.split('.')
    all_accepted = True
    for i in xrange(len(ip_fields)): 
      if not field_accepted(ip_fields[i], iprange_fields[i]):
        all_accepted = False
    if all_accepted:
      return True  
  return False

def check_connections(config_file):    
  known_ips = getKnownIps(config_file)
  connections = getConnections(config_file)
  foreign_ips = [c.foreign_ip for c in connections]
  unknown_connections = [c for c in connections if not recognize (c.foreign_ip, known_ips)]
  out = []
  if unknown_connections:
    out.append('--UNKNOWN CONNECTIONS--')
    out.append('User Process Local Remote')
    aux = ["%s %s %s:%s <=> %s:%s" % (c.user, c.process_name, c.local_hostname, c.local_service, c.foreign_hostname, c.foreign_service) for c in unknown_connections]
    out.extend(aux)  
  return out

if __name__=='__main__':
  print '\n'.join(check_connections("config.xml"))
