from hashlib import sha256
from uuid import uuid4
import sqlite3
import getpass
import os
import os.path

##
# Prints a header for the configuration script
def print_header():
	print '       == DODSCP CONFIGURATION SCRIPT =='
	print ' '
	print 'This program will configure DODSCP for your use.'
	print 'It is intended to be run before configuring your '
	print 'web server and launching the application.'
	print ' '

##
# Writes the configuration file
def write_file(db, sk, path):
	# TODO: Verify we can write to the file. If not, print out what
	#       should be in the file, so the user can copy-paste once 
	#       their permissions issue is resolved.
	fo = open('testconfig.py', 'w+')
	fo.write('DATABASE = "' + db + '"\n')
	fo.write('SECRET_KEY = "' + sk + '"\n')
	fo.write('SCRIPT = "' + path + '"\n')
	fo.close()

##
# Configure DODSCP
def main():
	print_header()
	
	#
	# CREATE DATABASE
	#
	print '* CREATING THE DATABASE *'
	dbname = raw_input('Enter the name of the DB to create (Default: dodscp.db): ')
	if not dbname:
		dbname = 'dodscp.db'

	con = sqlite3.connect(dbname)

	print ' '
	print '* CREATING DATABASE SCHEMA *'

	cur = con.cursor()

	cur.executescript("""
		DROP TABLE IF EXISTS loggedactions;
		CREATE TABLE loggedactions(id INTEGER PRIMARY KEY AUTOINCREMENT, user INTEGER, action INTEGER, time TEXT);
		DROP TABLE IF EXISTS actions;
		CREATE TABLE actions(id INTEGER PRIMARY KEY AUTOINCREMENT, action TEXT);
		INSERT INTO "actions" VALUES(1,'Successful login');
		INSERT INTO "actions" VALUES(2,'Failed login');
		INSERT INTO "actions" VALUES(3,'Logout');
		INSERT INTO "actions" VALUES(4,'Server started');
		INSERT INTO "actions" VALUES(5,'Server restarted');
		INSERT INTO "actions" VALUES(6,'Server stopped');
		INSERT INTO "actions" VALUES(7,'Server updated');
		INSERT INTO "actions" VALUES(8,'Reset own password');
		INSERT INTO "actions" VALUES(9,'Reset another''s password');
		INSERT INTO "actions" VALUES(10,'Created user');
		INSERT INTO "actions" VALUES(11,'Deleted user');
		INSERT INTO "actions" VALUES(12,'Modified user''s admin status');
		DROP TABLE IF EXISTS users;
		CREATE TABLE users(id INTEGER PRIMARY KEY AUTOINCREMENT, login TEXT, password TEXT, salt TEXT, isAdmin INTEGER);
		""")

	#
	# ADMIN PASSWORD
	#
	print ' '
	print '* SETTING ADMIN PASSWORD *'
	passmatch = False
	while not passmatch:
		pass1 = getpass.getpass('Enter ADMIN password: ')
		pass2 = getpass.getpass('Confirm ADMIN password: ')
		if pass1 == pass2:
			passmatch = True
		else:
			passmatch = False
			print 'Passwords do not match. Please try again.'

	salt = uuid4().hex
	hashed = sha256(pass2.encode() + salt.encode()).hexdigest()
	cur = con.execute('INSERT INTO users(login, password, salt, isAdmin) VALUES (?,?,?,?)', ('ADMIN', hashed, salt, 1))
	con.commit()

	#
	# SECRET KEY
	#
	print ' '
	print '* GENERATING SECRET_KEY *'
	sk = uuid4().hex

	#
	# SCRIPT NAME
	#
	print ' '
	print '* SETTING SCRIPT NAME *'
	print 'The path you enter should be the full path to the Linux '
	print 'Game Server Managers script (e.g. /home/sean/csgoserver)'
	goodscript = False
	while not goodscript:
		script = raw_input('Enter the path to the script: ')
		if os.path.isfile(script) and os.access(script, os.R_OK):
			# script exists and is readable
			goodscript = True
			if not os.access(script, os.X_OK):
				print script + ' is not executable. Please fix that.'
		else:
			goodscript = False
			print script + ' does not exist or is not readable. Try again.'

	#
	# GENERATE CONFIGURATION FILE
	#
	print ' '
	print '* GENERATING CONFIGURATION FILE *'
	write_file(dbname, sk, script)

	print ' '
	print '! DODSCP CONFIGURATION COMPLETE !'
	print ' '

if __name__ == '__main__':
	main()