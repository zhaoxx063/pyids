"""
  Module responsible for parsing the config file and give to the rest of
  modules the correct parameters.

"""

import Level
import validations
import os
from xml.dom import minidom

def getPatternsFile(config_file):
  """Wrapper to search_config to find the pattern file."""
  
  xmldoc = minidom.parse(config_file)
  logs_section_rl = xmldoc.getElementsByTagName("logs")
  logs_section_rf = logs_section_rl[0]
  pattern_file_rl = logs_section_rf.getElementsByTagName("pattern_file")
  return pattern_file_rl[0].lastChild.data
  
def getLogfiles(config_file):
  """Wrapper to search_config to find the logfiles to be monitorized."""
  
  xmldoc = minidom.parse(config_file)
  reflist = xmldoc.getElementsByTagName("logs")
  logs_node = reflist[0]
  logfiles_node_list = logs_node.getElementsByTagName("log")
  return [node.firstChild.data for node in logfiles_node_list]
     
def getModuleIntervals(config_file):
  """
    Returns a dictionary where keys are name modules 
    and values are the intervals that PyIDS will wait
    before repeating the check in default mode.
  
  """
   
  xmldoc = minidom.parse(config_file)
  reflist = xmldoc.getElementsByTagName("interval")
  result = {}
  for eachElement in reflist:
    module = eachElement.parentNode.tagName
    interval = eachElement.firstChild.data
    result[module] = float(interval)
    
  return result

def getMemoryLevels(config_file):
  xmldoc = minidom.parse(config_file)
  reflist = xmldoc.getElementsByTagName("memory")
  memory_node = reflist[0]
  levels_node_list = memory_node.getElementsByTagName("level")
  result = []
  for level_node in levels_node_list:
    level = Level.Level()
    
    percentage_rl = level_node.getElementsByTagName("percentage")   
    level.percentage = percentage_rl[0].firstChild.data
    
    minutes_rl = level_node.getElementsByTagName("minutes")
    level.minutes = minutes_rl[0].firstChild.data
    
    priority_rl = level_node.getElementsByTagName("priority")
    level.priority = priority_rl[0].firstChild.data
    
    result.append(level)
    
  return result
  
def getLsofCommand(config_file):
  """Get the lsof full path from the config file."""
  
  xmldoc = minidom.parse(config_file)
  lsof_path_rl = xmldoc.getElementsByTagName("lsof_path")
  lsof_path_rf = lsof_path_rl[0]
  return lsof_path_rf.lastChild.data

def getTimestampsFile(config_file):
  """Get the timestamps full path from the config file."""
  
  xmldoc = minidom.parse(config_file)
  timestamps_file_rl = xmldoc.getElementsByTagName("timestamps")
  timestamps_file_rf = timestamps_file_rl[0]
  return timestamps_file_rf.lastChild.data


def getLogFile(config_file):
  """Get the full path for the log file used by default."""

  xmldoc = minidom.parse(config_file)
  logfile_file_rl = xmldoc.getElementsByTagName("logfile")
  logfile_file_rf = logfile_file_rl[0]
  return logfile_file_rf.lastChild.data

def getGroupEmails(config_file):
  """Get the list of emails where PyIDS will send the alerts."""
  
  xmldoc = minidom.parse(config_file)
  emails_reflist = xmldoc.getElementsByTagName("emails")
  email_node = emails_reflist[0]
  email_addr_elems = email_node.getElementsByTagName("email")
  result = []
  
  result = [email.lastChild.data for email in email_addr_elems]
    
  group_emails = result
  for email in group_emails:
    validations.validateEmailAddress(email)
  return group_emails
  
def getEmailServer(config_file):
  """Get the email server from the config file."""

  xmldoc = minidom.parse(config_file)
  emails_reflist = xmldoc.getElementsByTagName("emails")
  emails_node = emails_reflist[0]
  smtp_node = emails_node.getElementsByTagName("smtp_server")
  return smtp_node[0].lastChild.data
  
def getSourceAddress(config_file):
  """Get the source address used in the outgoing mail from config file."""
  
  xmldoc = minidom.parse(config_file)
  emails_reflist = xmldoc.getElementsByTagName("emails")
  emails_node = emails_reflist[0]
  source_node = emails_node.getElementsByTagName("source_email")
  source_addr = source_node[0].lastChild.data
  
  if source_addr:
    validations.validateEmailAddress(source_addr)
  return source_addr
  
def getDatabaseFile(config_file):
  """Get the database filename from config file."""
  
  xmldoc = minidom.parse(config_file)
  database_file_rl = xmldoc.getElementsByTagName("database_file")
  database_file_rf = database_file_rl[0]
  return database_file_rf.lastChild.data

def getKnownIps(config_file):
  """
    Return a list with the ips considered known retrieved from the config file.
  
  """
  
  xmldoc = minidom.parse(config_file)
  connections_nodelist = xmldoc.getElementsByTagName("connections")
  connection_node = connections_nodelist[0]
  ipranges_nodelist = connection_node.getElementsByTagName("iprange")
  known_ips = [iprange_node.lastChild.data for iprange_node in ipranges_nodelist]
  
  for iprange in known_ips:
    validations.validateIPRange(iprange)
  
  return known_ips

def getACLS(config_file):
  
  xmldoc = minidom.parse(config_file)
  acls_nodelist = xmldoc.getElementsByTagName("acls")
  acls_node = acls_nodelist[0]
  rules_nodelist = acls_node.getElementsByTagName("rule")
  result = []
  
  for rule_node in rules_nodelist:
    user_nodelist = rule_node.getElementsByTagName("user")
    user_list = user_nodelist[0].lastChild.data
    
    executable_nodelist = rule_node.getElementsByTagName("executable")
    executable_list = executable_nodelist[0].lastChild.data
    
    port_nodelist = rule_node.getElementsByTagName("port")
    port_list = port_nodelist[0].lastChild.data
   
    protocol_nodelist = rule_node.getElementsByTagName("protocol")
    protocol_list = protocol_nodelist[0].lastChild.data
    
    result.append((user_list, executable_list, port_list, protocol_list))
  
  return result
    
def getChecksumFileList(config_file):
  xmldoc = minidom.parse(config_file)
  checksums_nodelist = xmldoc.getElementsByTagName("checksums")
  checksums_node = checksums_nodelist[0]
  file_nodelist = checksums_node.getElementsByTagName("file")
  checksum_file_list = [filename.lastChild.data for filename in file_nodelist]
  
  stack=[]
  not_recursive_dirs=[]
  result=[]

  #If a directory is found to be tested in the configuration, all the files
  #under it, including those inside subdirectories, are added
  #to the file list to be checksum monitored
  
  for filename in checksum_file_list:
    if filename[0] == '!':
      stack.append((filename[1:], 1))
    elif filename[0].isdigit():
      stack.append((filename[1:], int(filename[0]))) 
    else:
      if os.path.isdir(filename):
        stack.append((filename, '*'))
      else:
        result.append(filename)
      
      
  while stack:
    directory, count = stack.pop()
    if directory not in not_recursive_dirs and count != 0:
      try:
        files = os.listdir(directory)
      except OSError:
        result.append(directory)
          
      filenames=[]
      for each_file in files:
        try:
          filenames.append(directory+'/'+each_file)
        except UnicodeDecodeError:
          pass
  
      for filename in filenames:
        if os.path.isdir(filename):
          new_count = count
          if new_count!='*': 
            new_count -= 1 
          stack.append((filename, new_count))
        else:
          result.append(filename)
            
  return result

if __name__ == '__main__':
  print len(getChecksumFileList("config.xml"))
