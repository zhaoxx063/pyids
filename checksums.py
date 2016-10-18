#!/usr/bin/python
# -*- coding: iso-8859-15 -*-
"""
  Module responsible of generating the checksum database and checking
  if checksums have changed.

"""
import md5
import pickle
from config_parser import getDatabaseFile
from config_parser import getChecksumFileList
import myexceptions
import progress

def crear_bd(file_list, verbose=False):
  """
    Responsible from generating the database from a file list.
    Returns two variables. The database and the output.
 
  """
  base_datos = {}
  out = []
  
  if verbose:
    remaining = len(file_list)
    p = progress.ProgressMeter(total=remaining)
  
  for filename in file_list:
    try:
      contenido = open(filename, 'r').read()
      objeto_md5 = md5.new(contenido)
      base_datos[filename] = objeto_md5.hexdigest()
      
      if verbose:
        remaining -= 1
        p.update(1)
    except IOError, value:
      out.append(str(value))
      #sys.exit(2)
  
  return base_datos, out

def load_database(dbfile):
  """
    Loads the database from the database filename. 
		Returns it as a dictionary.

  """
  try:
    database_file = open(dbfile, 'r')
    database = pickle.load(database_file)
    database_file.close()  
    return database
  except IOError, (errno, strerrnor):
    raise myexceptions.ChecksumsError, \
          "[Error] Could not load database: %s" % strerrnor
  except:
    raise myexceptions.ChecksumsError, \
          "[Error] Could not load database: File has not got a valid format"

def comparar_bds(old, new):
  """
		Compares two databases. Typically the old and the new database.
	  Returns two variables. The list of differences and some output.

  """
  diferencias = []
  out = []
  for fichero, md5digest in old.iteritems():
    if fichero in new:
      if new[fichero] != old[fichero]:
        diferencias.append(fichero)
    else:
      msg = "[ALERT] File dissapeared: %s" % fichero
      out.append(msg)
  for filename, md5digest in new.iteritems():
    if filename not in old:
      msg = "[ALERT] New file found: %s" % filename
      out.append(msg)
  return diferencias, out


def check_checksums(config_file, verbose):
  """
    Gets the config_file and checks if the checksums of the files have changed.

  """
  file_list = getChecksumFileList(config_file)
  dbfile = getDatabaseFile(config_file)
  old_database = load_database(dbfile)
  return check_checksums_inside(file_list, old_database, verbose) 
  
def check_checksums_inside(file_list, old_database, verbose=False):
  """
    Internal function to check if the checksums have changed.
    The parameters are the file list (in order to generate the new database)
    and the old database.

  """		
  out = []
  bd_actual, outaux = crear_bd(file_list, verbose)
  out.extend(outaux)
  diferencias, outaux = comparar_bds(old_database, bd_actual)
  out.extend(outaux)
  if diferencias or out:
    out.insert(0, "CHECKSUMS")  
    for item in diferencias:
      out.append(str(item))
  return out

def generate_db(config_file, verbose):
  """Returns the database given the config_file."""
  database_filename = getDatabaseFile(config_file)
  try:
    open(database_filename, "r")
    raise myexceptions.ChecksumsError, \
          "[Error] Could not store database: filename %s exists" % database_filename
  except IOError:
    file_list = getChecksumFileList(config_file)
    return generate_db_inside(file_list, database_filename, verbose)

def generate_db_inside(file_list, database_filename, verbose):
  """
    Internal function to generate the database given the file list
    and the database filename.

  """
  
  bd_nueva, out = crear_bd(file_list, verbose)  
  output_file = open(database_filename, 'w')
  pickle.dump(bd_nueva, output_file)
  output_file.close()
    
  if out:
    out.insert(0, "[Warning] Database generated with errors")
    return out
  else:
    return ["[OK] Database generated successfully"]
  
if __name__ == "__main__":
  import datetime
  print datetime.datetime.now()
  print check_checksums("config.xml", verbose=False)
# generate_db("config.xml")
