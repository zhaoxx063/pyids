from subprocess import Popen, PIPE
from tools import execute

class Process:
  def __init__(self, pid, percentage, command, minutes):
    self.pid = pid
    self.percentage = percentage
    self.command = command
    self.minutes = minutes
    self.violated_levels = []
  
  def __init__(self):
    self.violated_levels = []

  def renice(self, priority):
    command = "renice "+ str(priority) + " " + str(self.pid)
    execute(command)
