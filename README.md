1. Use -h option to get usage.
Usage:./cipher -e FILENAME -k INITKEY [-g]  #INITKEY can be arbitrary string with length less than 256 bytes. Open debug info with -g option.
      ./cipher -d FILENAME

2. Example
./cipher -e ms_rule.xml -k test  #Encrypt ms_rule.xml with init key 'test', the encrypted data will be written to ms_rule.data
./cipher ms_rule.data            #Decrypt the ms_rule.data file
