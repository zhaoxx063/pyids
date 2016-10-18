#! /usr/bin/python 
# -*- coding: iso-8859-15 -*-
"""Main module of PyIDS."""

import sys
import datetime
from optparse import OptionParser
import socket

import memory
import checksums
import acls
import connections
import logs
import myexceptions

from Output import Output
from tools import getModuleTurns

def main():
  """Main function of Pyids."""
  
  if len(sys.argv) == 1:
    print ("%s: an option should be specified" % sys.argv[0])
    print ("Try '%s -h' or '%s --help' for more information" % (sys.argv[0], sys.argv[0]))
    sys.exit(2)

  parser = OptionParser()

  parser.add_option("-c", "--checksum", action="store_true", dest="check_checksums", help="check the filesystem checksums")
  parser.add_option("-m", "--memory", action="store_true", dest="check_memory", help="check the cpu used by processes in memory")
  parser.add_option("-a", "--acls", action="store_true", dest="check_acls", help="check that acls are being respected")
  parser.add_option("-u", "--unkips", action="store_true", dest="check_connections", help="check if there exist connections from or to unknown IP addresses")
  parser.add_option("-p", "--patterns", action="store_true", dest="check_logs", help="search attack patterns in logfiles")
  parser.add_option("-d", "--default", action="store_true", dest="default", help="options are read from config file")
  parser.add_option("-g", "--generate", action="store_true", dest="generate_db", help="generate the database and store the filesystem checksums")
  parser.add_option("-e", "--email", dest="email", default=False, help="send report to email")
  parser.add_option("-l", "--logfile", dest="logfile", default=False, help="log report to logfile []")
  parser.add_option("-q", "--quiet", action="store_true", dest="quiet", help="*do not* print to standard output")
  parser.add_option("-v", "--verbose", action="store_true", dest="verbose", help="print extra information to standard output")
  parser.add_option("-f", "--config", dest="config_file", default="config.xml", help="indicate an alternate config file")
  
  (options, args) = parser.parse_args()

  output = Output(options)

  report_list = []
  
  if options.default:
    turns = getModuleTurns(options.config_file)
    options.check_memory = turns['memory']
    options.check_checksums = turns['checksums']
    options.check_acls = turns['acls']
    options.check_connections = turns['connections']
    try:
      options.check_logs = turns['logs']
    except KeyError:
      options.check_logs = True
  if options.check_memory:
    if options.verbose: print "[*] Checking memory"
    report_list.extend(memory.check_memory(options.config_file))
  if options.check_checksums:
    if options.verbose: print "[*] Checking checksums"
    report_list.extend(checksums.check_checksums(options.config_file, options.verbose))
  if options.generate_db:
    if options.verbose: print "[*] Generating checksum database"
    try:
      report_list.extend(checksums.generate_db(options.config_file, options.verbose))
    except myexceptions.ChecksumsError, e:
      print e.message
      sys.exit(1)
  if options.check_acls:
    if options.verbose: print "[*] Checking acls"
    report_list.extend(acls.check_acls(options.config_file))
  if options.check_connections:
    if options.verbose: print "[*] Checking connections"
    report_list.extend(connections.check_connections(options.config_file))
  if options.check_logs:
    if options.verbose: print "[*] Checking logs"
    report_list.extend(logs.check_logs(options.config_file))
    
  if report_list:
    report_list.insert(0, 'Subject: [PyIDS] Alerts from '+socket.gethostname())
    report_list.insert(1, 'Time -> '+str(datetime.datetime.now()))
    report_list.insert(2, 'Host -> '+socket.gethostname()+'\n')
    if options.verbose and options.default:
      print report_list
    output.send(report_list)

if __name__ == "__main__":
  main()

