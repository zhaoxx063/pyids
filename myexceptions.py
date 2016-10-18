class ChecksumsError(Exception):
  def __init__(self, message):
    self.message = message
  def __str__(self):
    return `self.message`

class ConfigParserError(Exception):
  def __init__(self, message):
    self.message = message
  def __str__(self):
    return `self.message`

class BadTimeFormatError(Exception):
  def __init__(self, message):
    self.message = message
  def __str__(self):
    return `self.message`

class FieldTypeError(Exception):
  def __init__(self, message):
    self.message = message
  def __str__(self):
    return `self.message`

class BadIPFormatError(Exception):
  def __init__(self, message):
    self.message = message
  def __str__(self):
    return `self.message`

class BadIPRangeFormatError(Exception):
  def __init__(self, message):
    self.message = message
  def __str__(self):
    return `self.message`

class BadSyntaxError(Exception):
  def __init__(self, message):
    self.message = message
  def __str__(self):
    return `self.message`
