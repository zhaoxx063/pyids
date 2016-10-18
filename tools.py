from subprocess import Popen, PIPE
from config_parser import getModuleIntervals
from config_parser import getTimestampsFile
import sys
import pickle
import time
import myexceptions

def execute(command):
  output = Popen(command, shell=True, stdout=PIPE, stderr=PIPE)  
  
  return output.stdout.readlines()

def getExecTimestamps(timestamps_file):
  try:
    f = open(timestamps_file,'r')
    timestamps = pickle.load(f)
    if type(timestamps) != type({}):
      raise myexceptions.BadSyntaxError("[Error] Bad syntax in timestamps file")
    f.close()
    return timestamps
  except IOError, args:
    print args
    print "Considering no previous executions"
    return {'memory':0.0,'acls':0.0,'checksums':0.0,'connections':0.0,'logs':0.0}   
  except IndexError:
    raise myexceptions.BadSyntaxError("[Error] Bad syntax in timestamps file")
    
def putExecTimestamps(timestamps_file, timestamps):
  try:
    f = open(timestamps_file,'w')
    pickle.dump(timestamps, f)
    f.close()
  except IOError, args:
    print args
    sys.exit()
  
def update_timestamps(timestamps, turns):
  for module, turn in turns.items():
    if turn:
      timestamps[module] = time.time() / 60.0
  
  return timestamps  

def calculate_turns(intervals, timestamps, minutes_from_epoch):
  turns = {}

  for module,interval in intervals.items():
    last_exec = timestamps[module]
    if (last_exec + interval) < minutes_from_epoch:
      turns[module] = True
      timestamps[module] = minutes_from_epoch
    else:
      turns[module] = False  
  
  return turns

def getModuleTurns(config_file):
  timestamps_file = getTimestampsFile(config_file)
  intervals = getModuleIntervals(config_file)

  timestamps = getExecTimestamps(timestamps_file)  
  
  turns = calculate_turns(intervals, timestamps, time.time()/60.0)
  timestamps = update_timestamps(timestamps, turns)
  
  putExecTimestamps(timestamps_file, timestamps)
  
  return turns

