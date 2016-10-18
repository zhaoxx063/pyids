import re
import myexceptions

def validateEmailAddress(email_address):
  ro = re.compile(r'^\S+@\S+\.\S+$')
  if not ro.match(email_address):
    raise myexceptions.ConfigParserError, "[Error] Syntax error in config file: invalid source address"

def validateInteger(integer):
  try:
    int(integer)
  except ValueError:
    raise myexceptions.ConfigParserError, "[Error] Syntax error in config file: found an interval that is not an integer"

def validateIP(ip):
  ro = re.compile(r'(^\d{2,3}(.\d{1,3}){3,3}$)')
  if not ro.match(ip):
    return False
  else:
    return True

def validateIPRange(iprange):
  ro = re.compile(r'(^\d{2,3}(-\d{2,3})?(\.(\d{1,3}(-\d{2,3})?|[*])){3}$)|(^\d{2,3}(\.\d{1,3}){3}(-\d{2,3}(\.\d{1,3}){3})?$)')
  if not ro.match(iprange):
    raise myexceptions.ConfigParserError("[Error] Syntax error in config file: invalid iprange format")

def validateTime(time):
  ro = re.compile(r'\d{2}:\d{2}:\d{2}')
  if not ro.match(time):
    raise myexceptions.BadTimeFormatError, "[Error] Time syntax error"
  hours, minutes, seconds = time.split(':')
  hours = int(hours)
  minutes = int(minutes)
  seconds = int(seconds)
  if (hours > 23) or (hours < 00) or (minutes > 59) or (minutes < 00) or (seconds > 59) or (seconds < 00):
    raise myexceptions.BadTimeFormatError("[Error] Time values error")
