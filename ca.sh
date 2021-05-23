#!/bin/bash
########
FILE_BACKUP=false
FILE_OVERWRITE=true
########
CA_KEY_BITS="4096"
CA_KEY_ALGO="AES-256-CBC"
CA_CERT_EXPIRE_DAYS="1825"
CA_CRL_DAYS="365"
CA_HASH_ALGO="sha512"
########
HOST_KEY_BITS="2048"
HOST_CERT_EXPIRE_DAYS="825"
HOST_HASH_ALGO="sha512"
#######
MIN_PASSWORD_LENGTH=4
MAX_PASSWORD_LENGTH=100
#######
declare -a CA_FOLDERS=("ca" "ca/database" "ca/database/certificates" "ca/config" "ca/wwwroot" "ca/public" "ca/private"  "hosts" "hosts/public" "hosts/private")
#######

#certificates
# - .spc (Windows)

#private key
#- .pvk (Windows)

#Containers
#- .p7b .p7c (PKCS#12 B64: Cert, CA Cert, Cert Chain)
#- .pfx, .p12 (PKCS#12 B64: Cert, CA Cert, Cert Chain, private Keys)
#- .pem (Cert, CA Cert, Cert Chain, private Keys)
#- .pvk (Windows)

# revoke
#Revoke a CertificatePermanent link for this heading
#openssl ca -revoke newcerts/username.pem#

#openssl ca -gencrl -out crl.pem


readInput() {

	local HINT="$1"

	read -p "$HINT: " input
	echo "$input"

}

readPasswordInput() {

	local HINT="$1"

	local PASSWORD=$(readInput "$HINT")

	if ([ ${#PASSWORD} -ge $MIN_PASSWORD_LENGTH ] && [ ${#PASSWORD} -le $MAX_PASSWORD_LENGTH ]); then

		echo "$PASSWORD"

	else 

		echo "ERROR: Password length must be between $MIN_PASSWORD_LENGTH and $MAX_PASSWORD_LENGTH"
		exit 1

	fi

}

getTimeStamp() {

	local TIMESTAMP=$(date "+%Y%m%d-%H%M%S")
	echo "$TIMESTAMP"

}

doBackup() {

	local INPUT_FILE="$1"
	local TIMESTAMP=$(getTimeStamp)

	if [ ! -e "$INPUT_FILE" ] ; then
    	echo "\nERROR: Input file for Backup not found <$INPUT_FILE>"
    	exit 1
	fi

	local BACKUP_FILE="$INPUT_FILE.$TIMESTAMP"

	cp -r $INPUT_FILE $BACKUP_FILE

	if [ ! -e"$BACKUP_FILE" ] ; then
    	echo "\nERROR: Output file for Backup not found <$BACKUP_FILE>"
    	exit 1
	fi

}

getCaFolder() {

	local ROOT_FOLDER="$1"
	local CA_CN="$2"	
	local CA_FOLDER="$ROOT_FOLDER/$CA_CN"
	echo "$CA_FOLDER"

}

createCaFolders() {

	local CA_FOLDER="$1"

	if [ ! -d "$CA_FOLDER" ] ; then

		echo -e "\nINFO: Creating CA folders for CA <$CA_FOLDER>"

		createFolder "$CA_FOLDER"

		for folder in "${CA_FOLDERS[@]}"
		do
		  	
		  	createFolder "$CA_FOLDER/$folder"

		done

	fi
}

checkCaFolders() {

	local CA_FOLDER="$1"

	if [ ! -d "$CA_FOLDER" ] ; then
		
		echo -e "\nERROR: CA folder is missing <$CA_FOLDER>"
		exit 1

	else

		echo -e "\nINFO: Checking CA folders for CA <$CA_FOLDER>"

		local errorcount=0

		for folder in "${CA_FOLDERS[@]}"
		do
		  	
			if [ ! -d "$CA_FOLDER/$folder" ] ; then
		
				echo -e "ERROR: CA folder is missing <$CA_FOLDER/$folder>"
				
				errorcount=$((errorcount+1))

			fi

		done

		if (( ${errorcount} > 0 )); then

			echo -e "ERROR: Data folder not valid <$CA_FOLDER>"
			exit 1

		fi


	fi
}

getFilePath() {

	local ROOT_FOLDER="$1"
	local CA="$2"


	local CN="$3"
	local TARGET="$4" # CA | HOST
	local VISIBILITY="$5" # public | private
	local FILE_TYPE="$6" # PRIVKEY | PUBKEY | CERT | SIGNKEY | SIGNCSR | SIGNCERT
	local FORMAT="$7" # PEM | DER

	local CA_FOLDER=$(getCaFolder "$ROOT_FOLDER" "$CA")

	local SUB_FOLDER=$(getSubfolderPath "$CN" "$TARGET" "$VISIBILITY" "$FILE_TYPE" "$FORMAT")

	echo "$CA_FOLDER/$SUB_FOLDER"
}

getSubfolderPath() {

	local CN="$1"
	local TARGET="$2" # CA | HOST
	local VISIBILITY="$3" # public | private
	local FILE_TYPE="$4" # PRIVKEY | PUBKEY | CERT | SIGNKEY | SIGNCSR | SIGNCERT
	local FORMAT="$5" # PEM | DER



	local TARGET_FILE_PREFIX=""

	if [ "$TARGET" = "ca" ]; then

		TARGET_FILE_PREFIX="$TARGET/$VISIBILITY/$CN"

	elif [ "$TARGET" = "hosts" ]; then

		TARGET_FILE_PREFIX="$TARGET/$VISIBILITY/$CN/$CN"

	else 

		exit 1

	fi

	local CER_EXT=""
	local CSR_EXT=""
	local CA_SERIAL_EXT=""
	local DB_EXT=""
	local CRL_EXT=""
	local SSLCONF_EXT=""
	local CRL_EXT=""
	local HTML_EXT=""

	if [ "$FORMAT" = "PEM" ]; then

		CER_EXT="pem.cer"
		KEY_EXT="pem.key"
		CSR_EXT="csr"
		CSR_EXT="csr"
		CRL_EXT="pem.crl"

	elif [ "$FORMAT" = "TXT" ]; then

		CRL_EXT="crl.number"

	elif [ "$FORMAT" = "HTML" ]; then

		HTML_EXT="html"

	elif [ "$FORMAT" = "DER" ]; then
		CER_EXT="der.cer"
		KEY_EXT="der.key"
		CSR_EXT="csr"
		CRL_EXT="der.crl"

	elif [ "$FORMAT" = "SRL" ]; then

		CA_SERIAL_EXT="srl"

	elif [ "$FORMAT" = "DB" ]; then

		DB_EXT="db"

	elif [ "$FORMAT" = "SSLCONFIG" ]; then

		SSLCONF_EXT="config"

	else
		echo "ERROR: Invalid Format <$FORMAT>"
		exit 1
	fi

	local FILE_NAME=""

	if [ "$FILE_TYPE" = "serial" ]; then

		FILE_NAME=$(getFileName $TARGET_FILE_PREFIX $CA_SERIAL_EXT )

    elif [ "$FILE_TYPE" = "indexhtml" ]; then

    	FILE_NAME="ca/wwwroot/index.html" 

    elif [ "$FILE_TYPE" = "key" ]; then

    	FILE_NAME=$(getFileName $TARGET_FILE_PREFIX $KEY_EXT $VISIBILITY )
 
    elif [ "$FILE_TYPE" = "database" ]; then

    	FILE_NAME=$(getFileName $TARGET_FILE_PREFIX $DB_EXT )

    elif [ "$FILE_TYPE" = "crl" ]; then

    	FILE_NAME=$(getFileName $TARGET_FILE_PREFIX $CRL_EXT )

    elif [ "$FILE_TYPE" = "sslconfig" ]; then

    	FILE_NAME=$(getFileName $TARGET_FILE_PREFIX $SSLCONF_EXT "openssl")

    elif [ "$FILE_TYPE" = "csr" ]; then

    	FILE_NAME=$(getFileName $TARGET_FILE_PREFIX $CSR_EXT )
  
    elif [ "$FILE_TYPE" = "cert" ]; then

    	FILE_NAME=$(getFileName $TARGET_FILE_PREFIX $CER_EXT )

    elif [ "$FILE_TYPE" = "sancert" ]; then

    	FILE_NAME=$(getFileName $TARGET_FILE_PREFIX $CER_EXT "san")

#    elif [ "$FILE_TYPE" = "signkey" ]; then#

#    	FILE_NAME=$(getFileName $TARGET_FILE_PREFIX $KEY_EXT $VISIBILITY "signing")#

#    elif [ "$FILE_TYPE" = "signcert" ]; then#

#    	FILE_NAME=$(getFileName $TARGET_FILE_PREFIX $CER_EXT $VISIBILITY "signing")

	else

   		echo "\nERROR: File type <$FILE_TYPE> NOT KNOWN"
   		exit 1

	fi	


	echo "$FILE_NAME"
}

getFileName() {

	local TARGET_FILE_PREFIX="$1"
	local EXTENTION="$2"
	local VISIBILITY="$3"
	local FILE_KIND="$4"

	if [[ "$#" = 2 ]]; then

		echo "$TARGET_FILE_PREFIX.$EXTENTION"

	elif [[ "$#" = 3 ]]; then

		echo "$TARGET_FILE_PREFIX-$VISIBILITY.$EXTENTION"

	elif [[ "$#" = 4 ]]; then

		echo "$TARGET_FILE_PREFIX-$VISIBILITY-$FILE_KIND.$EXTENTION"
	
	else

		echo "ERROR: Error creating Filename - invalid arguments"
		exit 1
	fi
}


createFolder(){

	local FOLDER="$1"
	echo -e "INFO: Creating Folder <$FOLDER>"

   	if [ ! -d "$FOLDER" ] ; then

   		mkdir "$FOLDER"

   	else

   		echo "ERROR: Folder $FOLDER already exists"

   	fi
}

printCmdInfo() {

	echo "CA mode:"
	echo -e "\t ./ca.sh ca data_folder ca_fqdn CC ST L O OU"
	echo -e "\t ./ca.sh ca '/Users/clemens/Desktop/ownca/data' 'ca.int.cleem.de' 'DE' 'BW' 'Bruchsal' 'cleem.de' 'int.cleem.de'"
	echo 
	echo "Host mode:"
	echo -e "\t ./ca.sh host data_folder ca_fqdn CC ST L O OU Subject SANLine"
	echo -e "\t ./ca.sh host '/Users/clemens/Desktop/ownca/data' 'ca.int.cleem.de' 'DE' 'BW' 'Bruchsal' 'cleem.de' 'int.cleem.de' 'DNS:host03.int.cleem.de,DNS:host03.cleem.de,IP:192.168.2.3'"
	exit 1
}

extractSubjectFromSan() {

	local SAN_LINE="$1"

	IFS=',' read -ra SAN_ENTRIES <<< "$SAN_LINE"

	local DNS_PREFIX="DNS:"

    for SAN_ENTRY in "${SAN_ENTRIES[@]}"; do
      # process "$i"

      if [[ $SAN_ENTRY = $DNS_PREFIX* ]]; then

		replacement=""
		echo "${SAN_ENTRY/$DNS_PREFIX/$replacement}" 
		break 

      fi 


    done
}

##### File display

showCsr() {

	local CSR_FILE="$1"

	if [ -f "$CSR_FILE" ] ; then 

		openssl req -verify -in "$CSR_FILE" -text -noout
    	
	else

		echo "\nERROR: CSR file not found <$CSR_FILE>"
		exit 1

   	fi
}

showPublicKey() {

	local PUBLIC_KEY_FILE="$1"

	if [ -f "$PUBLIC_KEY_FILE" ] ; then 

		openssl rsa -in "$PUBLIC_KEY_FILE" -pubin -noout -text
    	
	else

		echo "\nERROR: Public key file not found <$PUBLIC_KEY_FILE>"
		exit 1

   	fi
}

showCert() {

	local CERT_FILE="$1"

	if [ -f "$CERT_FILE" ] ; then 

		openssl x509 -in "$CERT_FILE" -text -noout
    	
	else

		echo "\nERROR: Cert file not found <$CERT_FILE>"
		exit 1

   	fi
}

showPrivateKey() {

	local PRIVATE_KEY_FILE="$1"

	if [ -f "$PRIVATE_KEY_FILE" ] ; then 

		openssl rsa -in "$PRIVATE_KEY_FILE" -check

	else

		echo "\nERROR: Private key file not found <$PRIVATE_KEY_FILE>"
		exit 1

   	fi
}

convertKeyToDer() {


	local PEM_KEY="$1"
	local DER_KEY="$2"
	local PASSWORD="$3"

	echo -e "INFO:\t\t PEM: <$PEM_KEY>"
	echo -e "INFO:\t\t DER: <$DER_KEY>"


	if ([ -f "$DER_KEY" ] && $FILE_BACKUP ) ; then 

		doBackup "$DER_KEY"
    	
   	fi


   	if ([ -f "$PEM_KEY" ] && ([ ! -f "$DER_KEY" ] || $FILE_OVERWRITE)) ; then


	   	if [[ "$#" = 2 ]]; then

		#	openssl rsa -in "$PEM_KEY" -pubout -outform DER -out "$DER_KEY"

		#	openssl rsa -in "$PEM_KEY" -pubout -outform DER -out "$DER_KEY"

 			openssl rsa -pubin -inform PEM -in "$PEM_KEY" -outform DER -out "$DER_KEY"



		elif [[ "$#" = 3 ]]; then

			openssl rsa -in "$PEM_KEY" -pubout -outform DER -out "$DER_KEY" -passin "pass:$PASSWORD"
		
		else

			echo "ERROR: Error creating converting key - invalid arguments"
			exit 1
		fi


		if [ -f "$DER_KEY" ] ; then 

			echo "INFO: DER Key created <$DER_KEY>"

		else

			echo "ERROR: Creating DER Key <$DER_KEY>"
			exit 1
    	
   		fi


	else

		echo "ERROR: Converting $PEM_KEY to DER"
		exit 1
	fi
}

convertCertToDer() {

	local PEM_CERT="$1"
	local DER_CERT="$2"

	echo -e "INFO:\t\t PEM: <$PEM_CERT>"
	echo -e "INFO:\t\t DER: <$DER_CERT>"


	if ([ -f "$DER_CERT" ] && $FILE_BACKUP ) ; then 

		doBackup "$DER_CERT"
    	
   	fi

   	if ([ -f "$PEM_CERT" ] && ([ ! -f "$DER_CERT" ] || $FILE_OVERWRITE)) ; then

   		openssl x509 -outform der -in "$PEM_CERT" -out "$DER_CERT"


		if [ -f "$DER_CERT" ] ; then 

			echo "INFO: DER Cert created <$DER_CERT>"

		else

			echo "ERROR: Creating DER Cert <$DER_CERT>"
			exit 1
    	
   		fi


	else

		echo "ERROR: Converting $PEM_CERT to DER"
		exit 1
	fi	
}

convertCrlToDer() {

	local PEM_CRL="$1"
	local DER_CRL="$2"

	echo -e "INFO:\t\t PEM: <$PEM_CRL>"
	echo -e "INFO:\t\t DER: <$DER_CRL>"

	if ([ -f "$PEM_CRL" ] && $FILE_BACKUP ) ; then 

		doBackup "$PEM_CRL"
    	
   	fi

   	if ([ -f "$PEM_CRL" ] && ([ ! -f "$DER_CRL" ] || $FILE_OVERWRITE)) ; then

 		openssl crl -inform PEM -in "$PEM_CRL" -outform DER -out "$DER_CRL"

		if [ -f "$DER_CRL" ] ; then 

			echo "INFO: DER CRL created <$DER_CRL>"

		else

			echo "ERROR: Creating DER CRL <$DER_CRL>"
			exit 1
    	
   		fi


	else

		echo "ERROR: Converting $PEM_CRL to DER"
		exit 1
	fi	
}

##### CA Related

echoToFile() {

	local FILE="$1"
	local CONTENT="$2"

	if ([ -f "$FILE" ] && $FILE_BACKUP ) ; then 

		doBackup "$FILE"
    	
   	fi

   	if ([ ! -f "$FILE" ] || $FILE_OVERWRITE ) ; then

   			echo "$CONTENT" > "$FILE"

   	else

   		echo "\nERROR: Can not write <$CONTENT> to <$FILE>"

   	fi
}

createSerialFile() {

	local SERIAL_FILE="$1"

   	if ([ ! -f "$SERIAL_FILE" ] || $FILE_OVERWRITE ) ; then

   			echoToFile "$SERIAL_FILE" "01"

   	else

   		echo "\nERROR: Can not create serial file $SERIAL_FILE"

   	fi
}

createCrlFile() {

	local CRL_FILE="$1"

   	if ([ ! -f "$CRL_FILE" ] || $FILE_OVERWRITE ) ; then

   			echoToFile "$CRL_FILE" "01"

   	else

   		echo "\nERROR: Can not create CRL file $CRL_FILE"

   	fi
}




createDBFile() {

	local DB_FILE="$1"

	if ([ -f "$DB_FILE" ] && $FILE_BACKUP ) ; then 

		doBackup "$DB_FILE"
    	
   	fi

   	if ([ ! -f "$DB_FILE" ] || $FILE_OVERWRITE ) ; then

   			echo "01" > "$DB_FILE"
   			cp /dev/null "$DB_FILE"
			cp /dev/null "$DB_FILE.attr"

   	else

   		echo "\nERROR: Can not create serial file $DB_FILE"

   	fi
}


generateCrlPemFile() {

	local CA_SSL_CONFIG_FILE="$1"
	local CA_CRL_FILE="$2"
	local PASSWORD="$3"

	if ([ -f "$CA_CRL_FILE" ] && $FILE_BACKUP ) ; then 

		doBackup "$CA_CRL_FILE"
    	
   	fi

   	if ([ ! -f "$CA_CRL_FILE" ] || $FILE_OVERWRITE ) ; then

   		openssl ca -config "$CA_SSL_CONFIG_FILE" \
     	 -gencrl -out "$CA_CRL_FILE" \
     	 -passin "pass:$PASSWORD"

   	else

   		echo "\nERROR: Can not create revocation file $DB_FILE"

   	fi
}




generateCertSubjectLine() {

	local CC="$1"
	local ST="$2"
	local L="$3"
	local O="$4"
	local OU="$5"
	local CN="$6"

	local SUBJECT="/C=$CC/ST=$ST/L=$L/O=$O/OU=$OU/CN=$CN"

	echo "$SUBJECT"
}

generateRootCaPrivateKey() {
	
	local CA_PRIVATE_KEY_FILE="$1"
	local PASSWORD="$2"

	echo -e "INFO: \t\t Key: <$CA_PRIVATE_KEY_FILE>"
	echo -e "INFO: \t\t Bits: <$CA_KEY_BITS>"
	echo -e "INFO: \t\t Key Algo: <$CA_KEY_ALGO>"

	if ([ -f "$CA_PRIVATE_KEY_FILE" ] && $FILE_BACKUP ) ; then 

		doBackup "$CA_PRIVATE_KEY_FILE"
    	
   	fi


	if ([ ! -f "$CA_PRIVATE_KEY_FILE" ] || $FILE_OVERWRITE ) ; then

		openssl genpkey \
				-algorithm rsa \
				-out $CA_PRIVATE_KEY_FILE \
				-$CA_KEY_ALGO -pkeyopt rsa_keygen_bits:$CA_KEY_BITS \
				-pass stdin <<<"$PASSWORD"

		if [ -f "$CA_PRIVATE_KEY_FILE" ] ; then 

			echo "INFO: Key created <$CA_PRIVATE_KEY_FILE>"

		else

			echo "ERROR: Creating key <$CA_PRIVATE_KEY_FILE>"
			exit 1
    	
   		fi


	else

		echo "ERROR: Creating $CA_PRIVATE_KEY_FILE"
		exit 1
	fi
}

generatePublicKey() {

	local PRIVATE_KEY_FILE="$1"
	local PUBLIC_KEY_FILE="$2"
	local PASSWORD="$3"

	echo -e "INFO: \t\t Private Key: <$PRIVATE_KEY_FILE>"
	echo -e "INFO: \t\t Public Key: <$PUBLIC_KEY_FILE>"


	if ([ -f "$PUBLIC_KEY_FILE" ] && $FILE_BACKUP ) ; then 

		doBackup "$PUBLIC_KEY_FILE"
    	
   	fi

   	if ([ -f "$PRIVATE_KEY_FILE" ] && ([ ! -f "$PUBLIC_KEY_FILE" ] || $FILE_OVERWRITE ))  ; then


		openssl rsa -in "$PRIVATE_KEY_FILE" \
				-pubout \
				-out "$PUBLIC_KEY_FILE" \
				-passin "pass:$PASSWORD"


		if [ -f "$PUBLIC_KEY_FILE" ] ; then 

			echo "INFO: Created public key <$PUBLIC_KEY_FILE>"

		else

			echo "ERROR: Creating public key <$PUBLIC_KEY_FILE>"
			exit 1
    	
   		fi

	else

		echo "ERROR: Creating $CA_CSR_FILE"
		exit 1
	fi
}



####### END OPENSSL #####
defaultBlock(){

	local SUBJECT="$1"
	local CA_CERT_FILE="$2"
	local CA_CRL_FILE="$3"

read -d '' CONFIG_PART <<END
 ############## default 

[ default ]
ca                      = rootca                    # CA name
dir                     = .                          # Top dir
base_url                = http://$SUBJECT            # CA base URL
aia_url                 = \$base_url/$CA_CERT_FILE   # CA certificate URL
crl_url                 = \$base_url/$CA_CRL_FILE    # CRL distribution point
name_opt                = multiline,-esc_msb,utf8    # Display UTF-8 characters

 #######

END

echo "$CONFIG_PART"


}

reqBlock(){

	local CA_KEY_BITS="$2"
	local CA_HASH_ALGO="$3"
	
read -d '' CONFIG_PART <<END
####### req

[ req ]
default_bits            = $CA_KEY_BITS          # RSA key size
encrypt_key             = yes                   # Protect private key
default_md              = $CA_HASH_ALGO         # MD to use
utf8                    = yes                   # Input is UTF-8
string_mask             = utf8only              # Emit UTF-8 strings
prompt                  = no                    # Don't prompt for DN
distinguished_name      = ca_dn                 # DN section
req_extensions          = ca_reqext             # Desired extensions

 #######

END

echo "$CONFIG_PART"

}

caDnBlock(){


	local C="$1"
	local O="$2"
	local OU="$3"
	local SUBJECT="$4"

read -d '' CONFIG_PART <<END
####### ca_dn

[ ca_dn ]
countryName             = $C
organizationName        = $O
organizationalUnitName  = $OU
#commonName              = Root CA $SUBJECT

 #######

END
echo "$CONFIG_PART"

}


caRegExtBlock(){

read -d '' CONFIG_PART <<END
####### ca_reqext

[ ca_reqext ]
keyUsage                = critical,keyCertSign,cRLSign
basicConstraints        = critical,CA:false
subjectKeyIdentifier    = hash

 #######

END

echo "$CONFIG_PART"

}

generalCaBlock(){

read -d '' CONFIG_PART <<END
####### ca

[ ca ]
default_ca              = root_ca               # The default CA section

 #######

END

echo "$CONFIG_PART"

}

rootCaBlock(){

	local SUBJECT="$1"
	local CA_CERT_FILE="$2"
	local CA_KEY_FILE="$3"
	local CA_CRL_FILE="$4"
	local CA_SERIAL_FILE="$5"
	local CA_INDEX_FILE="$6"
	local DEFAULT_DAYS="$7"
	local DEFAULT_CRL_DAYS="$8"


read -d '' CONFIG_PART <<END
####### root_ca

[ root_ca ]
certificate             = \$dir/data/$SUBJECT/$CA_CERT_FILE       # The CA cert
private_key             = \$dir/data/$SUBJECT/$CA_KEY_FILE # CA private key
new_certs_dir           = \$dir/data/$SUBJECT/ca/database/certificates      # Certificate archive
serial                  = \$dir/data/$SUBJECT/$CA_SERIAL_FILE # Serial number file
crlnumber               = \$dir/data/$SUBJECT/$CA_CRL_FILE # CRL number file
database                = \$dir/data/$SUBJECT/$CA_INDEX_FILE # Index file
unique_subject          = no                    # Require unique subject
default_days            = $DEFAULT_DAYS         # How long to certify for
default_md              = $CA_HASH_ALGO         # MD to use
policy                  = match_pol             # Default naming policy
email_in_dn             = no                    # Add email to cert DN
preserve                = no                    # Keep passed DN ordering
name_opt                = \$name_opt             # Subject DN display options
cert_opt                = ca_default            # Certificate display options
copy_extensions         = none                  # Copy extensions from CSR
x509_extensions         = signing_ca_ext        # Default cert extensions
default_crl_days        = $DEFAULT_CRL_DAYS     # How long before next CRL
crl_extensions          = crl_ext               # CRL extensions

 #######

END

echo "$CONFIG_PART"

}


staticBlocks(){

read -d '' CONFIG_PART <<END
####### static
[ v3_ca ]
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always,issuer
basicConstraints = CA:true

[ match_pol ]
countryName             = match                 # Must match the Country
stateOrProvinceName     = optional              # Included if present
localityName            = optional              # Included if present
organizationName        = match                 # Must match 'Org Name'
organizationalUnitName  = optional              # Included if present
commonName              = supplied              # Must be present

[ any_pol ]
domainComponent         = optional
countryName             = optional
stateOrProvinceName     = optional
localityName            = optional
organizationName        = optional
organizationalUnitName  = optional
commonName              = optional
emailAddress            = optional

[ root_ca_ext ]
keyUsage                = critical,keyCertSign,cRLSign
basicConstraints        = critical,CA:true
subjectKeyIdentifier    = hash
authorityKeyIdentifier  = keyid:always

[ signing_ca_ext ]
keyUsage                = critical,keyCertSign,cRLSign
basicConstraints        = critical,CA:true,pathlen:0
subjectKeyIdentifier    = hash
authorityKeyIdentifier  = keyid:always
authorityInfoAccess     = @issuer_info
crlDistributionPoints   = @crl_info

[ crl_ext ]
authorityKeyIdentifier  = keyid:always
authorityInfoAccess     = @issuer_info

[ issuer_info ]
caIssuers;URI.0         = \$aia_url

[ crl_info ]
URI.0                   = \$crl_url

 #######

END

echo "$CONFIG_PART"


}

####### END OPENSSL #####

createOpenSslConfig (){

	CONFIG_FILE="$1"

	C="$2"
	O="$3"
	OU="$4"
	CN="$5"

	local P_CA_CERT_FILE=$(getSubfolderPath "$CN" "ca" "public" "cert" "PEM")
	local P_CA_KEY_FILE=$(getSubfolderPath "$CN" "ca" "private" "key" "PEM") 
	local P_CA_CRL_FILE=$(getSubfolderPath "$CN" "ca" "private" "crl" "TXT") 
	local P_CA_CRL_DER_FILE=$(getSubfolderPath "$CN" "ca" "public" "crl" "DER") 
	local P_CA_SERIAL_FILE=$(getSubfolderPath "$CN" "ca" "database" "serial" "SRL") 
	local P_CA_INDEX_FILE=$(getSubfolderPath "$CN" "ca" "database" "database" "DB") 



	if ([ -f "$CONFIG_FILE" ] && $FILE_BACKUP ) ; then 

		doBackup "$CONFIG_FILE"
    	
   	fi

   	if ( [ ! -f "$CONFIG_FILE" ] || $FILE_OVERWRITE )  ; then


				echo -e "INFO: \t\t CA Cert: <$P_CA_CERT_FILE>"
				echo -e "INFO: \t\t CA Key: <$P_CA_KEY_FILE>"
				echo -e "INFO: \t\t CA CRL: <$P_CA_CRL_FILE>"
				echo -e "INFO: \t\t CA CRL DER: <$P_CA_CRL_DER_FILE>"
				echo -e "INFO: \t\t CA Serial: <$P_CA_SERIAL_FILE>"
				echo -e "INFO: \t\t CA Database: <$P_CA_INDEX_FILE>"
				echo -e "INFO: \t\t CA Config File: <$CONFIG_FILE>"


			DEFAULT_BLOCK=$(defaultBlock "$CN" "$P_CA_CERT_FILE" "$P_CA_CRL_DER_FILE")
			REQ_BLOCK=$(reqBlock "$CA_KEY_BITS" "$CA_HASH_ALGO")
			CADN_BLOCK=$(caDnBlock "$C" "$O" "$OU" "$CN")
			CAREGEXT_BLOCK=$(caRegExtBlock)
			GENERALCA_BLOCK=$(generalCaBlock)
			ROOT_CA_BLOCK=$(rootCaBlock "$CN" "$P_CA_CERT_FILE" "$P_CA_KEY_FILE" "$P_CA_CRL_FILE" "$P_CA_SERIAL_FILE" "$P_CA_INDEX_FILE" "$CA_CERT_EXPIRE_DAYS" "$CA_CRL_DAYS" )
			STATIC_BLOCK=$(staticBlocks)

			OUTPUT=""
			OUTPUT+="$DEFAULT_BLOCK"
			OUTPUT+="$REQ_BLOCK"
			OUTPUT+="$CADN_BLOCK"
			OUTPUT+="$CAREGEXT_BLOCK"
			OUTPUT+="$GENERALCA_BLOCK"
			OUTPUT+="$ROOT_CA_BLOCK"
			OUTPUT+="$STATIC_BLOCK"

			echo -e "$OUTPUT" > $CONFIG_FILE
		


		if [ -f "$CONFIG_FILE" ] ; then 

			echo "INFO: Created config <$CONFIG_FILE>"

		else

			echo "ERROR: Creating config <$CONFIG_FILE>"
			exit 1
    	
   		fi

	else

		echo "ERROR: Creating $CONFIG_FILE"
		exit 1
	fi
}

generateRootCaCert() {


	local CA_SSL_CONFIG_FILE="$1"
	local CA_CSR_FILE="$2"
	local CA_CERT_FILE="$3"	
	local CA_CSR_SUBJECT_LINE="$4"	
	local PASSWORD="$5"


	echo -e "INFO: \t\t SSL Config: <$CA_SSL_CONFIG_FILE>"
	echo -e "INFO: \t\t CSR: <$CA_CSR_FILE>"
	echo -e "INFO: \t\t Cert: <$CA_CERT_FILE>"
	echo -e "INFO: \t\t Subject Line: <$CA_CSR_SUBJECT_LINE>"


	if ([ -f "$CA_CERT_FILE" ] && $FILE_BACKUP ) ; then 

		doBackup "$CA_CERT_FILE"
    	
   	fi


	if ([ -f "$CA_CSR_FILE" ] && ([ ! -f "$CA_CERT_FILE" ] || $FILE_OVERWRITE ))  ; then
	

		openssl ca -selfsign \
			-batch \
		    -in "$CA_CSR_FILE" \
		    -out "$CA_CERT_FILE" \
		    -extensions root_ca_ext \
		    -config "$CA_SSL_CONFIG_FILE" \
			-days "$CA_CERT_EXPIRE_DAYS" \
			-subj "$CA_CSR_SUBJECT_LINE" \
			-passin "pass:$PASSWORD"


		if [ -f "$CA_CERT_FILE" ] ; then 

			echo "INFO: Created CA root cert <$CA_CERT_FILE>"

			showCert "$CA_CERT_FILE"


		else

			echo "ERROR: Creating  CA root cert <$CA_CERT_FILE>"
			exit 1
    	
   		fi


	else

		echo "ERROR: Creating $CA_CERT_FILE"
		exit 1

	fi	
}

cleanUpDotOldFiles() {

	local REF_FILE="$1"

	PARENT_FOLDER=${REF_FILE%/*}

	echo "INFO: Cleaning Folder <$PARENT_FOLDER>"

	for OLD_FILE in $PARENT_FOLDER/*.old
	do

	    if [ -f "${OLD_FILE}" ]; then
	   
	    echo "INFO: Deleting <$OLD_FILE>";
	    rm $OLD_FILE

	    fi

	done


}

generateCsr() {

	local MODE="$1"
	local CA_SSL_CONFIG_FILE="$2"
	local KEY_FILE="$3"
	local CSR_FILE="$4"	
	local CSR_SUBJECT_LINE="$5"	
	local CERT_EXPIRE_DAYS="$6"
	local HASH_ALGO="$7"
	local SAN_LINE="$8"
	local PASSWORD="$9"


	echo -e "INFO: \t\t Mode: <$MODE>"
	echo -e "INFO: \t\t SSL Config: <$CA_SSL_CONFIG_FILE>"
	echo -e "INFO: \t\t Key: <$KEY_FILE>"
	echo -e "INFO: \t\t CSR: <$CSR_FILE>"
	echo -e "INFO: \t\t Subject: <$CSR_SUBJECT_LINE>"
	echo -e "INFO: \t\t SAN: <$SAN_LINE>"
	echo -e "INFO: \t\t Expire Days: <$CERT_EXPIRE_DAYS>"
	echo -e "INFO: \t\t Hash Algo: <$HASH_ALGO>"


	if ([ -f "$CA_CSR_FILE" ] && $FILE_BACKUP ) ; then 

		doBackup "$CA_CSR_FILE"
    	
   	fi


	if ([ -f "$KEY_FILE" ] && ([ ! -f "$CSR_FILE" ] || $FILE_OVERWRITE ))  ; then



		if [[ "$MODE" = "ca" ]]; then

		openssl req -new -key "$KEY_FILE" \
				-subj "$CSR_SUBJECT_LINE" \
				-config "$CA_SSL_CONFIG_FILE" \
				-out "$CSR_FILE" \
				-days "$CERT_EXPIRE_DAYS" \
				-"$HASH_ALGO" \
				-passin "pass:$PASSWORD" 


		elif [[ "$MODE" = "host" ]]; then



			openssl req -new -"$HASH_ALGO" \
			    -key "$KEY_FILE" \
			    -subj "$CSR_SUBJECT_LINE" \
			    -reqexts SAN \
			    -config <(cat "$CA_SSL_CONFIG_FILE" \
			        <(printf "\n[SAN]\nsubjectAltName=$SAN_LINE")) \
			    -out "$CSR_FILE" \
			    -passin "pass:$PASSWORD"


		else

			echo "ERROR: Invalid Mode <$MODE>"
			exit 1

		fi



		if [ -f "$CSR_FILE" ] ; then 

			echo "INFO: Created csr <$CSR_FILE>"

		else

			echo "ERROR: Creating csr <$CSR_FILE>"
			exit 1
    	
   		fi


	else

		echo "ERROR: Creating $CSR_FILE"
		exit 1
	fi	
}

signCsr() {

	local CA_SSL_CONFIG_FILE="$1"

	local SUBJECT="$2"

	local CSR_FILE="$3"	

	local CERT_FILE="$4"

	local PASSWORD="$5"



	echo -e "INFO: \t\t SSL Config: <$CA_SSL_CONFIG_FILE>"
	echo -e "INFO: \t\t Subject: <$SUBJECT>"
	echo -e "INFO: \t\t CSR: <$CSR_FILE>"
	echo -e "INFO: \t\t Cert: <$CERT_FILE>"


	if ([ -f "$CERT_FILE" ] && $FILE_BACKUP ) ; then 

		doBackup "$CERT_FILE"
    	
   	fi

   	if ([ ! -f "$CERT_FILE" ] || $FILE_OVERWRITE ) ; then

   		if [ ! -f "$CSR_FILE" ]; then

   			echo "ERROR: CSR $CSR_FILE does not exist"
   			exit 1

   		else

   			echo "$SUBJECT"
		   	openssl ca \
		   	-batch \
		    -config "$CA_SSL_CONFIG_FILE" \
		    -in "$CSR_FILE" \
		    -out "$CERT_FILE" \
		    -passin "pass:$PASSWORD" \
		    -subj "$SUBJECT" \
		    -extensions signing_ca_ext
		   


			if [ -f "$CERT_FILE" ] ; then 

				echo "INFO: Created cert <$CERT_FILE>"
				showCert "$CERT_FILE"

			else

				echo "ERROR: Creating cert <$CERT_FILE>"
				exit 1
	    	
	   		fi

		fi
	else

		echo "ERROR: Can not create cert $CERT_FILE"

	fi
}

signCsrSAN() {

	local CA_SSL_CONFIG_FILE="$1"
	local CSR_FILE="$2"	
	local CERT_FILE="$3"
	local PASSWORD="$4"
	local SUBJECT_SAN_LINE="$5"
	local SUBJECT="$6"
	local HOST_CERT_EXPIRE_DAYS="$7"

	echo -e "INFO: \t\t SSL Config: <$CA_SSL_CONFIG_FILE>"
	echo -e "INFO: \t\t CSR: <$CSR_FILE>"
	echo -e "INFO: \t\t Cert: <$CERT_FILE>"
	echo -e "INFO: \t\t SAN Line: <$SUBJECT_SAN_LINE>"

	if ([ -f "$CERT_FILE" ] && $FILE_BACKUP ) ; then 

		doBackup "$CERT_FILE"
    	
   	fi

   	if ([ ! -f "$CERT_FILE" ] || $FILE_OVERWRITE ) ; then

   		if ([ -f "$CSR_FILE" ] && [ -f "$CA_SSL_CONFIG_FILE" ]  ) ; then
 \
   			openssl ca \
		   	-batch \
		    -config "$CA_SSL_CONFIG_FILE" \
		    -subj "$SUBJECT" \
		    -in "$CSR_FILE" \
		    -out "$CERT_FILE" \
		    -passin "pass:$PASSWORD" \
		    -days "$HOST_CERT_EXPIRE_DAYS" \
		 	-extensions v3_ca \
		 	-extfile <(echo "[v3_ca]"; echo "basicConstraints = CA:FALSE"; echo "extendedKeyUsage=serverAuth, clientAuth, emailProtection"; echo "keyUsage = nonRepudiation, digitalSignature, keyEncipherment" ; echo "subjectAltName=$SUBJECT_SAN_LINE") \


			if [ -f "$CERT_FILE" ] ; then 

				echo "INFO: Created cert <$CERT_FILE>"
				showCert "$CERT_FILE"

			else

				echo "ERROR: Creating cert <$CERT_FILE>"
				exit 1
	    	
	   		fi


		else

			echo "ERROR: Input precondition not met"

		fi
	else

		echo "ERROR: Can not create cert $CERT_FILE"

	fi
}

##### Host Related

generateHostPrivateKey() {
	
	local HOST_PRIVATE_KEY_FILE="$1"
	local PASSWORD="$2"

	echo -e "INFO: \t\t Key: <$HOST_PRIVATE_KEY_FILE>"
	echo -e "INFO: \t\t Bits: <$HOST_KEY_BITS>"

	if ([ -f "$HOST_PRIVATE_KEY_FILE" ] && $FILE_BACKUP ) ; then 

		doBackup "$HOST_PRIVATE_KEY_FILE"
    	
   	fi


	if ([ ! -f "$HOST_PRIVATE_KEY_FILE" ] || $FILE_OVERWRITE ) ; then

		openssl genrsa \
				-out "$HOST_PRIVATE_KEY_FILE" \
				"$HOST_KEY_BITS" \
				-pass stdin <<<"$PASSWORD"

		if [ -f "$HOST_PRIVATE_KEY_FILE" ] ; then 

			echo "INFO: Created host key <$HOST_PRIVATE_KEY_FILE>"

		else

			echo "ERROR: Creating host key <$HOST_PRIVATE_KEY_FILE>"
			exit 1
    	
   		fi


	else

		echo "ERROR: Creating $HOST_PRIVATE_KEY_FILE"
		exit 1
	fi
}


createIndexHtml() {

	local CA_NAME="$1"
	local HTML_FILE="$2"
	local CA_PUBLIC_CERT="$3"
	local CA_CRL="$4"


read -d '' HTML_PAGE <<END
<!DOCTYPE html>

<html>
<head>
  <meta http-equiv="Content-Type" content="text/html; charset=utf-8"/>
  <title>CA - $CA_NAME</title>
 <!-- <LINK href="styles.css" rel="stylesheet" type="text/css"> -->
</head>

<body>

<p>
<h1>$CA_NAME</h1>
<h2>Files</h2>

</br>
<a href="$CA_PUBLIC_CERT">CA Certificate</a>
</br>
<a href="$CA_CRL">CA Certificate Revocation List</a>
</p>

</body>
</html>
END



			echo -e "$HTML_PAGE" > $HTML_FILE
		


		if [ -f "$HTML_FILE" ] ; then 

			echo "INFO: Created HTML <$HTML_FILE>"

		else

			echo "ERROR: Creating HTML <$HTML_FILE>"
			exit 1
    	
   		fi



}



##### Mode related

createCA() {

	local ROOT_FOLDER="$1"
	local CC="$2"
	local ST="$3"
	local L="$4"
	local O="$5"
	local OU="$6"
	local CN="$7"

	
	local CA_FOLDER=$(getCaFolder "$ROOT_FOLDER" "$CN")

	echo -e "\nINFO: Creating CA <$CN> into <$CA_FOLDER>"


	if ([ -d "$CA_FOLDER" ] && $FILE_BACKUP ) ; then 

		echo -e "\nINFO: Creating Backup for CA <$CA_FOLDER>"
		doBackup "$CA_FOLDER"
    	
   	fi

   	if ([ ! -d "$CA_FOLDER" ] || $FILE_OVERWRITE )  ; then

  		# CREATE FOLDERS
		createCaFolders "$CA_FOLDER"


		# USED FILES
   		local CA_SERIAL_FILE=$(getFilePath "$ROOT_FOLDER" "$CN" "$CN" "ca" "database" "serial" "SRL") 
   		local CA_DATABASE_FILE=$(getFilePath "$ROOT_FOLDER" "$CN" "$CN" "ca" "database" "database" "DB") 
   		local CA_CRL_FILE_TXT=$(getFilePath "$ROOT_FOLDER" "$CN" "$CN" "ca" "private" "crl" "TXT") 
		local CA_CRL_FILE_PEM=$(getFilePath "$ROOT_FOLDER" "$CN" "$CN" "ca" "public" "crl" "PEM") 
		local CA_CRL_FILE_DER=$(getFilePath "$ROOT_FOLDER" "$CN" "$CN" "ca" "public" "crl" "DER") 
   		local CA_SSL_CONFIG_FILE=$(getFilePath "$ROOT_FOLDER" "$CN" "$CN" "ca" "config" "sslconfig" "SSLCONFIG") 
   		local CA_HTML_INDEX_FILE=$(getFilePath "$ROOT_FOLDER" "$CN" "$CN" "ca" "wwwroot" "indexhtml" "HTML") 




		local CA_PRIVATE_KEY_FILE_PEM=$(getFilePath "$ROOT_FOLDER" "$CN" "$CN" "ca" "private" "key" "PEM") 
		local CA_PRIVATE_KEY_FILE_DER=$(getFilePath "$ROOT_FOLDER" "$CN" "$CN" "ca" "private" "key" "DER") 
		local CA_PUBLIC_KEY_FILE_PEM=$(getFilePath "$ROOT_FOLDER" "$CN" "$CN" "ca" "public" "key" "PEM")
		local CA_PUBLIC_KEY_FILE_DER=$(getFilePath "$ROOT_FOLDER" "$CN" "$CN" "ca" "public" "key" "DER")


		local CA_CERT_CSR_FILE=$(getFilePath "$ROOT_FOLDER" "$CN" "$CN" "ca" "public" "csr" "PEM")

		local CA_CERT_FILE_PEM=$(getFilePath "$ROOT_FOLDER" "$CN" "$CN" "ca" "public" "cert" "PEM")


		local CA_CERT_FILE_DER=$(getFilePath "$ROOT_FOLDER" "$CN" "$CN" "ca" "public" "cert" "DER")
		
		local CA_CERT_FILE_DER_RELATIVE=$(getSubfolderPath "$CN" "ca" "public" "cert" "DER")
		local CA_CRL_FILE_DER_RELATIVE=$(getSubfolderPath "$CN" "ca" "public" "crl" "DER") 


		local CA_CERT_SUBJECT_LINE=$(generateCertSubjectLine "$CC" "$ST" "$L" "$O" "$OU" "$CN")
	
		local CA_SAN_LINE="DNS:ca.int.cleem.de"

		# CREATING CA SERIAL
		echo -e "\nINFO: Creating CA serial file <$CA_SERIAL_FILE>"
		createSerialFile "$CA_SERIAL_FILE"

		echo -e "\nINFO: Creating CA CRL TXT file <$CA_CRL_FILE_TXT>"
		createCrlFile "$CA_CRL_FILE_TXT"

		echo -e "\nINFO: Creating CA database file <$CA_DATABASE_FILE>"
		createDBFile "$CA_DATABASE_FILE"

		# ASKING FOR USER INPUT OF PASSWORDS
		echo -e "\nINFO: Setting RSA Key passwords"
		local ROOT_KEY_PASSWORD=$(readPasswordInput "CA private key password")

		# CREATING CA PRIVATE KEY IN PEM FORMAT
		echo -e "\nINFO: Creating CA private key PEM <$CA_PRIVATE_KEY_FILE_PEM>"
		generateRootCaPrivateKey "$CA_PRIVATE_KEY_FILE_PEM" "$ROOT_KEY_PASSWORD"

		# CREATING CA PRIVATE KEY IN DER FORMAT
		echo -e "\nINFO: Creating CA private key DER <$CA_PRIVATE_KEY_FILE_DER>"
		convertKeyToDer "$CA_PRIVATE_KEY_FILE_PEM" "$CA_PRIVATE_KEY_FILE_DER" "$ROOT_KEY_PASSWORD"

		# CREATING CA PUBLIC KEY IN PEM FORMAT
		echo -e "\nINFO: Creating CA public key PEM <$CA_PUBLIC_KEY_FILE_PEM>"
		generatePublicKey "$CA_PRIVATE_KEY_FILE_PEM" "$CA_PUBLIC_KEY_FILE_PEM" "$ROOT_KEY_PASSWORD"
		
		# CREATING CA PUBLIC KEY IN DER FORMAT
		echo -e "\nINFO: Creating CA public key DER <$CA_PUBLIC_KEY_FILE_DER>"
		convertKeyToDer "$CA_PUBLIC_KEY_FILE_PEM" "$CA_PUBLIC_KEY_FILE_DER"

		echo -e "\nINFO: Creating CA OpenSSL config File <$CA_SSL_CONFIG_FILE>"
		createOpenSslConfig "$CA_SSL_CONFIG_FILE" "$CC" "$O" "$OU" "$CN"


		echo -e "\nINFO: Creating CA CSR <$CA_CERT_CSR_FILE>"
		generateCsr "ca" "$CA_SSL_CONFIG_FILE" "$CA_PRIVATE_KEY_FILE_PEM" "$CA_CERT_CSR_FILE" "$CA_CERT_SUBJECT_LINE" "$CA_CERT_EXPIRE_DAYS" "$CA_HASH_ALGO" "$CA_SAN_LINE" "$ROOT_KEY_PASSWORD"


		# CREATING CA CERT IN PEM FORMAT
		echo -e "\nINFO: Creating CA root cert PEM <$CA_CERT_FILE_PEM>"
		generateRootCaCert "$CA_SSL_CONFIG_FILE" "$CA_CERT_CSR_FILE" "$CA_CERT_FILE_PEM" "$CA_CERT_SUBJECT_LINE" "$ROOT_KEY_PASSWORD"
		cleanUpDotOldFiles "$CA_DATABASE_FILE"
	
		# CREATING CA CERT IN DER FORMAT
		echo -e "\nINFO: Creating CA root cert DER <$CA_CERT_FILE_DER>"
		convertCertToDer "$CA_CERT_FILE_PEM" "$CA_CERT_FILE_DER"

		echo -e "\nINFO: Creating CA Certificate revocation file PEM <$CA_CRL_FILE_PEM>"
		generateCrlPemFile "$CA_SSL_CONFIG_FILE" "$CA_CRL_FILE_PEM" "$ROOT_KEY_PASSWORD"
		cleanUpDotOldFiles "$CA_CRL_FILE_TXT"

		echo -e "\nINFO: Creating CA Certificate revocation file DER <$CA_CRL_FILE_DER>"
		convertCrlToDer "$CA_CRL_FILE_PEM" "$CA_CRL_FILE_DER" 

		createIndexHtml "$CN" "$CA_HTML_INDEX_FILE" "$CA_CERT_FILE_DER_RELATIVE" "$CA_CRL_FILE_DER_RELATIVE"



		# RESETTING VARIABLES
		ROOT_KEY_PASSWORD=""
		SIGNING_KEY_PASSWORD=""

	else

		echo "ERROR Creating CA $CN in Folder $CA_FOLDER"
		exit 1

	fi
}

createHost() {

	local ROOT_FOLDER="$1"

	local CC="$2"
	local ST="$3"
	local L="$4"
	local O="$5"
	local OU="$6"
	local P_SUBJECT="$7"
	local CA=$8
	local SAN_CONTENT="$9" 

	local CA_FOLDER=$(getCaFolder "$ROOT_FOLDER" "$CA")

	local HOST_CERT_SUBJECT_LINE=$(generateCertSubjectLine "$CC" "$ST" "$L" "$O" "$OU" "$P_SUBJECT")



	echo -e "INFO: \t\t Country: <$CC>"
	echo -e "INFO: \t\t State: <$ST>"
	echo -e "INFO: \t\t Location: <$L>"
	echo -e "INFO: \t\t Organisation key: <$O>"
	echo -e "INFO: \t\t Organisation unit: <$OU>"
	echo -e "INFO: \t\t Subject: <$P_SUBJECT>"
	echo -e "INFO: \t\t CA: <$CA>"
	echo -e "INFO: \t\t SAN Line: <$SAN_CONTENT>"


	### CA Specific files needed to sign
	local CA_SSL_CONFIG_FILE=$(getFilePath "$ROOT_FOLDER" "$CA" "$CA" "ca" "config" "sslconfig" "SSLCONFIG") 
	local CA_DATABASE_FILE=$(getFilePath "$ROOT_FOLDER" "$CA" "$CA" "ca" "database" "database" "DB") 
   		

	### Host Specific files needed to sign
	local HOST_PRIVATE_KEY_FILE_PEM=$(getFilePath "$ROOT_FOLDER" "$CA" "$P_SUBJECT" "hosts" "private" "key" "PEM") 
	local HOST_PRIVATE_KEY_FILE_DER=$(getFilePath "$ROOT_FOLDER" "$CA" "$P_SUBJECT" "hosts" "private" "key" "DER") 


	local HOST_PUBLIC_KEY_FILE_PEM=$(getFilePath "$ROOT_FOLDER" "$CA" "$P_SUBJECT" "hosts" "public" "key" "PEM") 
	local HOST_PUBLIC_KEY_FILE_DER=$(getFilePath "$ROOT_FOLDER" "$CA" "$P_SUBJECT" "hosts" "public" "key" "DER") 
	

	local HOST_KEY_CSR_FILE=$(getFilePath "$ROOT_FOLDER" "$CA" "$P_SUBJECT" "hosts" "public" "csr" "PEM")

	local HOST_CERT_FILE_PEM=$(getFilePath "$ROOT_FOLDER" "$CA" "$P_SUBJECT" "hosts" "public" "cert" "PEM")
	local HOST_CERT_FILE_DER=$(getFilePath "$ROOT_FOLDER" "$CA" "$P_SUBJECT" "hosts" "public" "cert" "DER")

	local HOST_SAN_CERT_FILE_PEM=$(getFilePath "$ROOT_FOLDER" "$CA" "$P_SUBJECT" "hosts" "public" "sancert" "PEM")
	local HOST_SAN_CERT_FILE_DER=$(getFilePath "$ROOT_FOLDER" "$CA" "$P_SUBJECT" "hosts" "public" "sancert" "DER")


	##### FLOW 
	echo -e "\nINFO: Checking CA Folders in <$CA_FOLDER>"
	checkCaFolders "$CA_FOLDER"

	echo -e "\nINFO: Creating CA Subfolders>"
    createFolder "$CA_FOLDER/hosts/public/$P_SUBJECT"
	createFolder "$CA_FOLDER/hosts/private/$P_SUBJECT"


	local PRIVATE_KEY_PASSWORD=$(readPasswordInput "CA private key password")
    local HOST_KEY_PASSWORD=$(readPasswordInput "Host private key password")


	echo -e "\nINFO: Creating Host key PEM <$HOST_PRIVATE_KEY_FILE_PEM>"
	generateHostPrivateKey "$HOST_PRIVATE_KEY_FILE_PEM" "$HOST_KEY_PASSWORD"

	echo -e "\nINFO: Creating Host key DER <$HOST_PRIVATE_KEY_FILE_DER>"
	convertKeyToDer "$HOST_PRIVATE_KEY_FILE_PEM" "$HOST_PRIVATE_KEY_FILE_DER" "$HOST_KEY_PASSWORD"

	echo -e "\nINFO: Creating Host public key PEM <$HOST_PUBLIC_KEY_FILE_PEM>"
	generatePublicKey "$HOST_PRIVATE_KEY_FILE_PEM" "$HOST_PUBLIC_KEY_FILE_PEM" "$HOST_KEY_PASSWORD"

	echo -e "\nINFO: Creating Host public key DER <$HOST_PUBLIC_KEY_FILE_DER>"
	convertKeyToDer "$HOST_PUBLIC_KEY_FILE_PEM" "$HOST_PUBLIC_KEY_FILE_DER"

	echo -e "\nINFO: Creating CSR <$HOST_KEY_CSR_FILE> for key <$HOST_PRIVATE_KEY_FILE_PEM>"
	generateCsr "host" "$CA_SSL_CONFIG_FILE" "$HOST_PRIVATE_KEY_FILE_PEM" "$HOST_KEY_CSR_FILE" "$HOST_CERT_SUBJECT_LINE" "$HOST_CERT_EXPIRE_DAYS" "$HOST_HASH_ALGO" "$SAN_CONTENT" "$PRIVATE_KEY_PASSWORD" 
	showCsr "$HOST_KEY_CSR_FILE"


	echo -e "\nINFO: Creating PEM Host cert <$HOST_CERT_FILE_PEM> via <$HOST_KEY_CSR_FILE>"
	signCsr "$CA_SSL_CONFIG_FILE" "$HOST_CERT_SUBJECT_LINE" "$HOST_KEY_CSR_FILE" "$HOST_CERT_FILE_PEM" "$PRIVATE_KEY_PASSWORD"

	cleanUpDotOldFiles "$CA_DATABASE_FILE"
	echo -e "\nINFO: Creating Host cert DER <$HOST_CERT_FILE_DER>"
	convertCertToDer "$HOST_CERT_FILE_PEM" "$HOST_CERT_FILE_DER"
	
	
	echo -e "\nINFO: Creating PEM Host SAN cert <$HOST_SAN_CERT_FILE_PEM> with content <$SAN_CONTENT>"
	signCsrSAN "$CA_SSL_CONFIG_FILE" "$HOST_KEY_CSR_FILE" "$HOST_SAN_CERT_FILE_PEM" "$PRIVATE_KEY_PASSWORD" "$SAN_CONTENT" "$HOST_CERT_SUBJECT_LINE" "$HOST_CERT_EXPIRE_DAYS"

	cleanUpDotOldFiles "$CA_DATABASE_FILE"

echo "########"

	echo -e "\nINFO: Creating Host SAN cert DER <$HOST_SAN_CERT_FILE_DER>"
	convertCertToDer "$HOST_SAN_CERT_FILE_PEM" "$HOST_SAN_CERT_FILE_DER"

exit 1


	ROOT_KEY_PASSWORD=""
	SIGNING_KEY_PASSWORD=""
}



##################################################### START

##### ARGS 
P_MODE="$1"
P_DATA_FOLDER="$2"
P_CA_FQDN="$3"
P_CC="$4"
P_ST="$5"
P_L="$6"
P_O="$7"
P_OU="$8"
P_SAN="$9"

##### Script flow

P_SUBJECT=$(extractSubjectFromSan "$P_SAN")

if ([[ "$P_MODE" = "ca" ]] && [[ "$#" = 8 ]]); then

	# CREATE A CA
	createCA "$P_DATA_FOLDER" "$P_CC" "$P_ST" "$P_L" "$P_O" "$P_OU" "$P_CA_FQDN" 

elif ([[ "$P_MODE" = "host" ]] && [[ "$#" = 9 ]]); then

	# CREATE A HOST
	createHost "$P_DATA_FOLDER" "$P_CC" "$P_ST" "$P_L" "$P_O" "$P_OU" "$P_SUBJECT" "$P_CA_FQDN" "$P_SAN"

else

	# COMPLAIN
	echo "ERROR: Invalid arguments"
	printCmdInfo

fi 
