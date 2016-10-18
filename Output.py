from config_parser import getGroupEmails
from config_parser import getLogFile
from config_parser import getEmailServer
from config_parser import getSourceAddress

class Output:
  def __init__(self, options):
    self.logfile = options.logfile
    self.email = options.email
    self.quiet = options.quiet
    self.default = options.default
    self.config_file = options.config_file
  def send(self, report_list):
    if self.logfile:
      if self.logfile == "default":
        self.logfile = getLogFile(self.config_file)
      
      try:
        f = open(self.logfile, 'a')
        f.write('\n')
        f.write('\n'.join(report_list))
        f.close()
      except IOError, args:
        print args
    
    if self.email or self.default:
      import smtplib
      smtpserver = getEmailServer(self.config_file)
      AUTHREQUIRED = 0 # if you need to use SMTP AUTH set to 1
      smtpuser = ''  # for SMTP AUTH, set SMTP username here
      smtppass = ''  # for SMTP AUTH, set SMTP password here
      
      RECIPIENTS = []
      if self.default or self.email == "default": 
        RECIPIENTS.extend(getGroupEmails(self.config_file))
      else:
        RECIPIENTS.append(self.email)
      
      SENDER = getSourceAddress(self.config_file)
      msg = '\n'.join(report_list)

      session = smtplib.SMTP(smtpserver)
      if AUTHREQUIRED:
        session.login(smtpuser, smtppass)
      smtpresult = session.sendmail(SENDER, RECIPIENTS, msg)
			
    if not self.quiet:
      print '\n'.join(report_list)
      
