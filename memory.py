#!/usr/bin/python
# -*- coding: iso-8859-15 -*-
from subprocess import Popen, PIPE
import sys
import pickle
import smtplib
import Process
import Level
from config_parser import getMemoryLevels
from tools import execute

import validations

def time_to_minutes(time):
  validations.validateTime(time)
  hours, minutes, seconds = time.split(':')
  return int(hours)*60 + int(minutes)

def determine_greedness(levels, processes):
  greed_processes = []
 
  for process in processes:
    for level in levels:
      if process.percentage >= level.percentage and process.minutes >= level.minutes:
        process.violated_levels.append(level)
  
  return [process for process in processes if process.violated_levels]

def search_greed_processes(levels):
  output = execute("ps -eo pid,pcpu,comm,time")
  
  processes = []
  
  for line in output:
    line = line.strip()
    data = line.split()
    
    if data[0].isdigit(): # avoid first line
      process = Process.Process()
      process.pid = int(data[0].strip())
      process.percentage = float(data[1].strip())
      process.command = data[2].strip()
      #Sometimes we get a time called <defunct> when the process is being closed
      #if we get this time ignore the process
      time = data[3].strip()
      if time != "<defunct>": 
        process.minutes = time_to_minutes(time)
        processes.append(process)
                                        
  return determine_greedness(levels, processes)
  
def check_memory(config_file):
  levels = getMemoryLevels(config_file)
  greed_processes = search_greed_processes(levels)
  output = []	
  if greed_processes:
    output.append("MEMORY")
    output.append("PID Percentage Command Minutes Action")
    for process in greed_processes:
      for level in process.violated_levels:
        output.append("%d\t%.2f\t%s\t%d\t%s" % (process.pid, process.percentage, process.command, process.minutes, "Renice " + str(level.priority)))
      
        process.renice(level.priority)            
  return output
  
if __name__=="__main__":
  import datetime
  t = datetime.datetime.now()
  output = open('pyids.log', 'a')
  output.write(str(t)+'\n')
  check_memory("config.xml")
