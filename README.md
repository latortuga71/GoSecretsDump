# GoSecretsDump
Basic Clone Of Impacket Secrets Dump 


Dump SAM And LSA Secrets With Golang.

## Install
* `go build -ldflags="-s -w" cmd\GoSecretsDump`

## Usage 
* `GoSecretsDump.exe -d hackerlab -u turtleadmin -p 123456 -h dc01 -v -remote`
* `GoSecretsDump.exe -d hackerlab -u turtleadmin -p 123456 -h dc01 -remote`
* `GoSecretsDump.exe -v`
* `GoSecretsDump.exe`

## Note
* Only Supports New Style AES Hashes.

## Credits
Thanks to the below projects and blogs to help with the many sticking points i encountered.
* https://github.com/C-Sto/gosecretsdump (Inspired me to do this because this wasnt working for me)
* https://www.insecurity.be/blog/2018/01/21/retrieving-ntlm-hashes-and-what-changed-technical-writeup/
* https://github.com/rapid7/metasploit-framework/blob/master/documentation/modules/post/linux/gather/hashdump.md
* https://github.com/SecureAuthCorp/impacket
* http://moyix.blogspot.com/2008/02/decrypting-lsa-secrets.html
* http://moyix.blogspot.com/2008/02/cached-domain-credentials.html
* http://moyix.blogspot.com/2008/02/syskey-and-sam.html
* https://github.com/CiscoCXSecurity/creddump7
* https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/Invoke-PowerDump.ps1
* https://github.com/G0ldenGunSec/SharpSecDump
