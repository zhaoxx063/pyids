#! /usr/bin/python
# -*- coding: iso-8859-15 -*-
"""
  Search attack patterns in logs.

"""

from config_parser import getLogfiles
from config_parser import getPatternsFile
import pickle

class SSHEntry:
  pass
  
def load_patterns(logfilename, config_file):
  """
    Returns a list of the patterns related to a logfile.
    
  """
  patterns_file = getPatternsFile(config_file)
  infile = open(patterns_file, 'r')
  patterns = pickle.load(infile)
  try:
    return patterns[logfilename]
  except KeyError:
    return []
  
def check_logs(config_filename):
  """
    Search each pattern in the corresponding log file.
    
  """
  logfilenames = getLogfiles(config_filename)
  offending_lines = []
  for logfilename in logfilenames:
    patterns = load_patterns(logfilename, config_filename)
    try:
      logfile = open(logfilename, 'r')
    except IOError, e:
      error = "[Warning!] Could not open %s: %s" % (e.filename, e.strerror)
      return ["--LOGS--", error]
    
    for line in logfile.readlines():
      for pattern in patterns:
        if pattern in line:
          offending_lines.append(line.strip())
  
  if offending_lines:
    output = summarize_logs(offending_lines)
    output.insert(0, '--LOGS--')
    return output
  else:
    return []
    
def summarize_logs(offending_lines):
  output = []
  ssh_entries = {}
  for line in offending_lines:
    data = line.split()

    ssh_entry = SSHEntry()
    ssh_entry.sshid = data[4].strip('sshd[]:')
    ssh_entry.date = ' '.join(data[0:2])
    ssh_entry.time = data[2]
    status = data[5]
    if status == 'Accepted':
      ssh_entry.result = 'Success'
      ssh_entry.user = data[8]
      ssh_entry.ip = data[10].lstrip(':f')
    else:
      if data[8] == 'invalid':
        ssh_entry.result = 'Invalid user'
        ssh_entry.user = data[10]
        ssh_entry.ip = data[12].lstrip(':f')
      else:
        ssh_entry.result = 'Invalid password'
        ssh_entry.user = data[8]
        ssh_entry.ip = data[10].lstrip(':f')

    if ssh_entry.ip not in ssh_entries.keys():
      ssh_entries[ssh_entry.ip] = []
    ssh_entries[ssh_entry.ip].append(ssh_entry)
  
  for ip, ssh_entry_list in ssh_entries.items():
    success_entries = [ssh_entry for ssh_entry in ssh_entry_list if ssh_entry.result == 'Success']
    invalid_user_entries = [ssh_entry for ssh_entry in ssh_entry_list if ssh_entry.result == 'Invalid user']
    invalid_password_entries = [ssh_entry for ssh_entry in ssh_entry_list if ssh_entry.result == 'Invalid password']
    output.append("IP: %s attempted to login %d times between %s %s and %s %s" % (ip, len(ssh_entry_list), ssh_entry_list[0].date, ssh_entry_list[0].time, ssh_entry_list[-1].date, ssh_entry_list[-1].time))
    if success_entries:
      users = []
      output.append("\t%d success connections" % len(success_entries))
      for ssh_entry in success_entries:
        if ssh_entry.user not in users:
          users.append(ssh_entry.user)
      output.append("\t\t users: %s" % ','.join(users))
    if invalid_user_entries:
      output.append("\t%d invalid user connections" % len(invalid_user_entries))
    if invalid_password_entries:  
      users = []
      output.append("\t%d invalid password connections" % len(invalid_password_entries))
      for ssh_entry in invalid_password_entries:
        if ssh_entry.user not in users:
          users.append(ssh_entry.user)
      output.append("\t\t users: %s" % ','.join(users))

  return output          
if __name__ == "__main__":
  import datetime
  print datetime.datetime.now()
  print '\n'.join(check_logs("config.xml"))
