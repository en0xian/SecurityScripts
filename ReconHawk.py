#!/usr/bin/python


#script to take list of sites and find subdomains using sublist3r

import sys, getopt
import subprocess
import os
from selenium import webdriver
from selenium.common.exceptions import NoSuchElementException,InvalidArgumentException,WebDriverException
from time import sleep

def scrape_domains(domain_file_path):
	os.mkdir("./Targets")
	domain_file = open(domain_file_path, "r")
	domains =  domain_file.read()
	domains = domains.split("\n")
	
	

	#scrape list of domains for subdomains and save them to file
	for domain in domains:
		if domain != "":
			print("[*] Scraping " + domain)
			os.mkdir("./Targets/"+domain)
			os.mkdir("./Targets/"+domain+"/Screenshots")
			process = subprocess.call("/usr/share/Sublist3r/sublist3r.py -d " + domain + " -o " + "./Targets/"+domain+"/"+"subdomains.txt " + "> /dev/null 2>&1", shell = True)
			
			#use httprobe to check which sites are allive
			print("[*] Scrape Complete, checking who is alive")
			process = subprocess.Popen(["cat", "./Targets/"+domain+"/"+"subdomains.txt"], stdout=subprocess.PIPE)
			alive_sites = subprocess.check_output(('/root/go/bin/httprobe'), stdin=process.stdout)
			alive_sites =  alive_sites.decode("utf-8")

			#Write results to file
			print("[*] Alive sites located, writing to file: " + "./Targets/"+domain+"/"+"alive.txt")
			alive = open("./Targets/"+domain+"/"+"alive.txt","w")
			alive.write(alive_sites)
			alive.close()

			#screenshot alive sites
			subdomain_to_screenshot = open("./Targets/"+domain+"/"+"alive.txt","r")
			subdomain_to_screenshot = subdomain_to_screenshot.read().split("\n")
			print("[*] Screenshotting alive subdomains for: " + domain)
			driver = webdriver.Firefox()
			for subdomain in subdomain_to_screenshot:
				try:
					driver.get(subdomain)
					sleep(5)
					if "https://" in subdomain:
						subdomain = subdomain.replace("https://", "")
						driver.save_screenshot("./Targets/"+domain+"/Screenshots/"+subdomain+"443"+".png")
					else:
						subdomain = subdomain.replace("http://", "")
						driver.save_screenshot("./Targets/"+domain+"/Screenshots/"+subdomain+"80"+".png")

				except InvalidArgumentException:
					print("[x] " + subdomain + " is not a valid domain... moving on")
					pass

				except WebDriverException:
					print("[x] " + subdomain + " errored out... moving on")
			driver.close()
			
		
		

	
	
		

def main(argv):
	print (

"""
__________                               ___ ___                __    
\______   \ ____   ____  ____   ____    /   |   \_____ __  _  _|  | __
 |       _// __ \_/ ___\/  _ \ /    \  /    ~    \__  \\ \/ \/ /  |/ /
 |    |   \  ___/\  \__(  <_> )   |  \ \    Y    // __ \\     /|    < 
 |____|_  /\___  >\___  >____/|___|  /  \___|_  /(____  /\/\_/ |__|_ \
        \/     \/     \/           \/         \/      \/            \/													
									by en0xian | version 1.1
"""
)

	try:
		opts,args = getopt.getopt(argv,"hf:",["file"])

	except getopt.GetoptError:
		print("ReconHawk.py -f </path/to/domain_file>")
		sys.exit(2)

	for opt, arg in opts:
		if opt == "-f":
			print("Scaping domains from file: " + arg)
			scrape_domains(arg)
		else:
			print("ReconHawk.py -f </path/to/domain_file>")

if __name__ == "__main__":
	main(sys.argv[1:])
