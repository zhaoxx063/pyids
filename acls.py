#!/usr/bin/python
# -*- coding: iso-8859-15 -
"""
  This module is responsible of checking if the access control lists to sockets
  are being respected by the system.

"""
  
import sys
from tools import execute
from config_parser import getACLS
from config_parser import getLsofCommand

def get_command(ps_output):
  """Returns the command string extracted from the output of a ps command."""
  valid_line = ps_output[1]
  data = valid_line.split()
  
  return data[0].strip(':')

def get_path(whereis_output):
  """Returns the full path of a command from the output of a whereis command."""
  if len(whereis_output) == 1:
    data = whereis_output[0]
  else:
    data = whereis_output[1]

  more_data = data.split()
  if len(more_data) < 2:
    return ""
  else:
    return more_data[1]
    
def pid_to_path(pid):
  """Returns the full path of the executable of a process given its pid."""
  ps_command = "ps -o command " + pid
  ps_output = execute(ps_command)
  
  command = get_command(ps_output)
  
  whereis_command = "whereis " + command
  whereis_output = execute(whereis_command)
  
  path = get_path(whereis_output)
  if path == "":
    return command
  else:
    return path
  
def search_services(servicio):
  """Returns the port number of a service given its name."""
  try:
    infile = open("/etc/services", 'r')
  except IOError:
    print "Failed to open /etc/services"
    sys.exit(2)

  for linea in infile.readlines():
    datos = linea.split()
    
    if len(datos) >= 2:
      if servicio == datos[0].strip():
        puer = datos[1].split('/')
        puerto = puer[0].strip()
        return puerto
      
def data_to_port(dato):
  """Returns the port number where an executable is running."""
  addresses = dato.split('->')
  return addresses[0].split(':')[1]

def execute_lsof(config_file):
  """Execute the lsof command and returns its output."""
  lsof_path = getLsofCommand(config_file)
  command = lsof_path + " -i -F pLTnP"
  return execute(command)

def extract_raw_executions(lsof_output):
  """Returns the executions of processes that open ports given a lsof_output."""
  executions = []
  pid = ""
  port = ""
  
  for line in lsof_output:
    if line[0] == 'p':
      if pid:
        executions.append((username, pid, port, protocol))
      pid = line[1:].strip()
    else:
      if line[0] == 'L':
        username = line[1:].strip()
#      elif line[0] == 'T':
#        if line[1:3] == 'ST':
#          estado = line.split('=')[1].strip()
      elif line[0] == 'P':
        protocol = line[1:].strip()
      elif line[0] == 'n':
        port = line[1:].strip()  
  
  if lsof_output:
    executions.append((username, pid, port, protocol))
  
  return executions

def get_executions(config_file):
  """From input gets a lsof output and returns a list of executions"""
  
  lsof_output = execute_lsof(config_file)
  
  raw_executions = extract_raw_executions(lsof_output)
  
  executions = []
  for raw_execution in raw_executions:
    path = pid_to_path(raw_execution[1])
    service = data_to_port(raw_execution[2])
    if not service.isdigit():
      port = search_services(service)
    else:
      port = service
    executions.append((raw_execution[0], path, port, raw_execution[3]))
  
  return executions

def accept_field(acl_field, tupla_field):
  """
    Returns true if a field of execution is accepted by an acl, 
    return false otherwise.
	
  """
  if acl_field == tupla_field:
    return True

  if acl_field == '*':
    return True
    
  if ',' in acl_field:
    if tupla_field in acl_field.split(','):
      return True
    
  if tupla_field.isdigit() and '-' in acl_field:
    low, high = acl_field.split('-')
    if int(low) <= int(tupla_field) <= int(high):
      return True
  
  return False

def accepts(acl, tupla):
  """Compares an acls and a tuple from an execution."""
  if acl == tupla:
    return True

  for i in xrange(len(tupla)):
    if not accept_field(acl[i], tupla[i]):
      return False
  
  return True

def is_in(tupla, acls):
  """
    Returns true if a tuple from an execution is accepted by one of 
    the acls inside an acls list.

  """
  for acl in acls:
    if accepts(acl, tupla):
      return True
  return False

def find_unallowed_executions(executions, acls):
  """Find the tuples not accepted by any acls."""
  return [tupla for tupla in executions if not is_in(tupla, acls)]
  
def tidy_output(differences):
  """Format the output given by other functions properly."""
  out = []
  if differences:
    out.append("--ACLS--")
    out.append("User Path Port Protocol")
    for item in differences:
      #if item[2] != None: #En algunos casos salían procesos con puerto None
      out.append("%s %s %s %s" % item)
      # En item queda un elemento que es el protocolo
      # no se usa en la salida normal
  return out

def check_acls(config_file):
  """Checks if the acls are being respected."""
  acls = getACLS(config_file)
  executions = get_executions(config_file)
  diferencias = find_unallowed_executions(executions, acls)
  out = tidy_output(diferencias)
  return out

if __name__ == "__main__":
  import datetime
  print datetime.datetime.now()
  print '\n'.join(check_acls("config.xml"))
