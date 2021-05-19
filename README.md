# bash-ca
Bash script to manage a CA

```sh
chmod +x ca.sh
./ca.sh
```

## CA Mode
You need to create CA first to use host mode
```sh
	 ./ca.sh ca data_folder ca_fqdn CC ST L O OU
	 ./ca.sh ca '/Users/bashca/ca' 'ca.example.net' 'DE' 'BW' 'Karlsruhe' 'example.net' 'ca.example.net'
```

## Host mode
```sh
Host mode:
	 ./ca.sh host data_folder ca_fqdn CC ST L O OU Subject
	 ./ca.sh host '/Users/bashca/ca' 'ca.example.net' 'DE' 'BW' 'Karlsruhe' 'example.net' 'ca.example.net' 'host01.example.net'
```
