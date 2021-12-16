#!/bin/bash

#TO-DO
#Install nuclei
#Install subfinder
#install assetfinder
#Install amass
#Install sublist3r
#Add sublist3r results to enumeration
#Add wayback URLs https://github.com/tomnomnom/waybackurls
#install gf patterns https://github.com/tomnomnom/gf https://github.com/1ndianl33t/Gf-Patt...

domain=$1
wordlist="/usr/share/wordlist/SecLists/Discovery/DNS/deepmagic.com-prefixes-top500.txt"
#resolvers="/path/to/dns_resolvers_textfile" #this is used also for shuffle dns, these are supposed to be a list of IPs associated to the scope of the target domain
#resolve_domain="/path/to/massdns/binary -r /path/to/massdns/lists/resolvers.txt -t A -o 5 -w" #massdns needed for shuffledns

domain_enum(){
	echo "[+] Running Domain Enumeration"
	mkdir -p $domain $domain/subdomains $domain/Intel $domain/Intel/nuclei
	echo "[+] Creating Subdirectories for" $domain
	subfinder -d $domain -o $domain/subdomains/subfinder.txt
	echo "[+] Starting AssetFinder"
	assetfinder -subs-only $domain | tee $domain/subdomains/assetfinder.txt
	echo "[+] Asset Finder Complete"
	echo "[+] Starting Amass For 25 minutes"
	amass enum -d $domain -o $domain/subdomains/amass.txt -timeout 25
	echo "[+] Amass Complete"
	echo "[+] Starting ShuffleDNS"
#	shuffldns -d $domain -w $wordlist -r $resolvers -o $domain/subdomains/shuffldns.txt
#	echo "[+] Shuffle DNS  Complete"
#	echo "[+] Scraping Complete, Outputting results to " $domain/subdomains/all.txt
	cat $domain/subdomains/*.txt > $domain/subdomains/all.txt
}

domain_enum

resolving_domains(){
	echo "[+] resolving domains"
	shuffledns -d $domain -list $domain/subdomains/all.txt -r $resolvers -o $domain/domains.txt #shuffledns can take every subdomain and resolve it against the ips in our scope
}

#resolving_domains

httpprobe(){
	echo "[+] Beginning HTTP Probe"
	cat $domain/subdomains/all.txt | /root/go/bin/httpx -threads 200 -o $domain/Intel/httpx.txt #this will tell us which hosts are alive
	echo "[+] HTTP Probe complete. Results Located @ " $domain/Intel/httpx.txt
}
httpprobe


#Aquatone Fly Over
aquatone_flyover(){
	echo  "[+] Beginning Aquatone Fly Over"
	cat $domain/Intel/httpx.txt | aquatone -out $domain/Intel/aquatone
	echo "[+] Aquatone Fly Over Complete"
	
}
aquatone_flyover

#aquatone_flyover

#scanner will use nuclei to begin looking at our hosts
scanner(){
	echo "[+] Nuclei Scanning Initialization "
	echo "[+] Nuclei Scanning For CVEs "
	cat $domain/Intel/httpx.txt | /root/go/bin/nuclei -t /root/Desktop/Bounties/Scripts/Automation/nuclei-templates/cves/ -c 100 -o $domain/Intel/nuclei/cves.txt
	echo "[+] Nuclei Scanning For Vulnerabilities "
	cat $domain/Intel/httpx.txt | /root/go/bin/nuclei -t /root/Desktop/Bounties/Scripts/Automation/nuclei-templates/vulnerabilities/ -c 100 -o $domain/Intel/nuclei/vulnerablities.txt
	echo "[+] Nuclei Scanning For Sensitive Files "
	cat $domain/Intel/httpx.txt | /root/go/bin/nuclei -t /root/Desktop/Bounties/Scripts/Automation/nuclei-templates/file/ -c 100 -o $domain/Intel/nuclei/files.txt
	echo "[+] Nuclei Scanning For subdomain take overs "
	cat $domain/Intel/httpx.txt | /root/go/bin/nuclei -t /root/Desktop/Bounties/Scripts/Automation/nuclei-templates/takeovers/ -c 100 -o $domain/Intel/nuclei/payloads.txt
	echo "[+] Nuclei Scanning For Exposed Panels "
	cat $domain/Intel/httpx.txt | /root/go/bin/nuclei -t /root/Desktop/Bounties/Scripts/Automation/nuclei-templates/exposed-panels/ -c 100 -o $domain/Intel/nuclei/generic.txt
	echo "[+] Nuclei Scanning Complete "
}

scanner

#now we use the wayback machine to scan theaggregated urls and look through to find any extensions listed below and return the port 80 and port 443s
wayback_data(){
echo "[+] Parsing Wayback Machine For URLS "
cat $domain/sources/all.txt | /root/go/bin/waybackurls | tee $domain/Intel/wayback/tmp.txt
cat $domain/Intel/wayback/tmp.txt | egrep -v "\.woff|\.ttf|\.svg|\.png|\.jpeg|\.jpg|\.svg|\.css|\.ico" | sed 's/:80//g;s/:443//g' | sort -u > $domain/Intel/wayback/wayback.txt
echo "[+] URLs parsed, find them here: " $domain/Intel/wayback/wayback.txt
rm  $domain/Intel/wayback/tmp.txt

}

wayback_data

#We will now fuzz the returned URLs and output that to a file called valid-temp.txt
valid_urls(){
	echo "[+] Validating URLs from wayback"
	ffuf -c -u "FUZZ" -w $domain/Intel/wayback/wayback.txt -of csv -o $domain/Intel/wayback/valid-temp.txt
	cat $domain/Intel/wayback/valid_tmp.txt | grep http | awk -F "," '{print %1}' >> $domain/Intel/wayback/valid.txt
	rm $domain/Intel/wayback/valid_temp.txt
	
}

valid_urls


gf_patterns(){
	echo "[+] Using GF to parse"
	gf xss $domain/Intel/wayback/valid.txt | tee $domain/Intel/gf/xss.txt
	gf sqli $domain/Intel/wayback/valid.txt | tee $domain/Intel/gf/sql.txt
	echo "[+] GF Complete, Find Result here" $domain/Intel/gf
} 
