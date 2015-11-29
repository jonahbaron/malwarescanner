#!/usr/bin/python

import sys
import subprocess
import os
from os import listdir


def getHashes(hashfile):
	with open(hashfile) as hfile:
		hashcontent = hfile.readlines()

	hashes = []

	for line in hashcontent:
		hashvalue = line.split(None, 1)[0]
		hashvalue = hashvalue.lower()
		hashes.append(hashvalue)

	return hashes

def getFiles(directory):
	files = []

	for path, subdirs, localfiles in os.walk(directory):
		for filename in localfiles:
			f = os.path.join(path, filename)
			files.append(f)

	return files

def checkHash(hashes,files):
	print "Scanning files"

	badFiles = []

	for h in hashes:
		print "Comparing files against hash - ", h

		for f in files:
			command = "md5sum " + f + " | awk '{ print $1 }'"
			fileHash = subprocess.check_output(command, shell=True)

			command = "strings " + f + " | md5sum | awk '{ print $1 }'"
			contentHash = subprocess.check_output(command, shell=True)

			fileHash = fileHash.rstrip()
			contentHash = contentHash.rstrip()
			
			#print fileHash
			#print contentHash

			if h == fileHash or h == contentHash:
				print "MALICIOUS FILE DETECTED - ", f
				badFiles.append(f)
	print ""

	return badFiles

def main():
	print "Malware scanner"
	print ""
	#print "Number of args: ", len(sys.argv)

	if len(sys.argv) < 2:
		print "Error - usage: scanner.py hashes [directory]"
		sys.exit(0)

	hashfile = sys.argv[1]
	directory = os.getcwd()

	if len(sys.argv) == 3:
		directory = sys.argv[2]

	#print "Arguments: ", hashfile, directory
	#print ""


	hashes = getHashes(hashfile)

	print "Hashes loaded"
	print len(hashes), " total"
	print "-----"
	for line in hashes:
		print line
	print ""

	files = getFiles(directory)

	print "Files identified"
	print len(files), " total"
	print "-----"
	for f in files:
		print f
	print ""

	badFiles = checkHash(hashes,files)

	print "Malicious files"
	print len(badFiles), " total"
	print "-----"
	if len(badFiles) == 0:
		print "No malware found"
	for f in badFiles:
		print f
	print ""

if __name__ == "__main__":
	main()
