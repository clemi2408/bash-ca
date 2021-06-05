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
declare -a CA_FOLDERS=("ca" "ca/database" "ca/database/certs" "ca/config" "ca/wwwroot" "ca/public" "ca/private"  "hosts" "hosts/public" "hosts/private")
#######

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
	local FILE_TYPE="$6" # PRIVKEY | PUBKEY | CERT | SIGNKEY | SIGNCSR | SIGNCERT | keycert ...
	local FORMAT="$7" # PEM | DER ...

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
	local KEY_CERT_EXT=""
	local RND_FILE_EXT=""
	local PFX_FILE_EXT=""
	local P7B_FILE_EXT=""

	if [ "$FORMAT" = "PEM" ]; then

		CER_EXT="pem.cer"
		KEY_EXT="pem.key"
		CSR_EXT="csr"
		CSR_EXT="csr"
		CRL_EXT="pem.crl"
		KEY_CERT_EXT="pem"

	elif [ "$FORMAT" = "P7B" ]; then

		P7B_FILE_EXT="p7b"

	elif [ "$FORMAT" = "PFX" ]; then

		PFX_FILE_EXT="p12"

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

	elif [ "$FORMAT" = "RND" ]; then

		RND_FILE_EXT="rnd"

	else
		echo "ERROR: Invalid Format <$FORMAT>"
		exit 1
	fi

	local FILE_NAME=""

	if [ "$FILE_TYPE" = "serial" ]; then

		FILE_NAME=$(getFileName $TARGET_FILE_PREFIX $CA_SERIAL_EXT )

    elif [ "$FILE_TYPE" = "indexhtml" ]; then

    	FILE_NAME="ca/wwwroot/index.html" 

    elif [ "$FILE_TYPE" = "randomfile" ]; then

    	FILE_NAME=$(getFileName $TARGET_FILE_PREFIX $RND_FILE_EXT $VISIBILITY )   	

    elif [ "$FILE_TYPE" = "key" ]; then

    	FILE_NAME=$(getFileName $TARGET_FILE_PREFIX $KEY_EXT $VISIBILITY )
 
    elif [ "$FILE_TYPE" = "keycert" ]; then

    	FILE_NAME=$(getFileName $TARGET_FILE_PREFIX $KEY_CERT_EXT "keycert" )
 
     elif [ "$FILE_TYPE" = "certkey" ]; then

    	FILE_NAME=$(getFileName $TARGET_FILE_PREFIX $KEY_CERT_EXT "certkey" )

     elif [ "$FILE_TYPE" = "pfx" ]; then

    	FILE_NAME=$(getFileName $TARGET_FILE_PREFIX $PFX_FILE_EXT )

     elif [ "$FILE_TYPE" = "p7b" ]; then

    	FILE_NAME=$(getFileName $TARGET_FILE_PREFIX $P7B_FILE_EXT )

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
	echo -e "INFO: \t\tCreating Folder <$FOLDER>"

   	if [ ! -d "$FOLDER" ] ; then

   		mkdir "$FOLDER"

   	else

   		echo -e "WARN: \t\tFolder $FOLDER already exists"

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
	echo 
	echo "Revoke host:"
	echo -e "\t ./ca.sh revoke data_folder ca_fqdn host_fqdn"
	echo -e "\t ./ca.sh revoke /Users/clemens/Desktop/ownca/data 'ca.int.cleem.de' 'host01.int.cleem.de'"

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
	local PASSWORD="$2"

	if [ -f "$PRIVATE_KEY_FILE" ] ; then 


		if [[ "$#" = 1 ]]; then

			openssl rsa -in "$PRIVATE_KEY_FILE"

		elif [[ "$#" = 2 ]]; then

			openssl rsa -in "$PRIVATE_KEY_FILE" -passin "pass:$PASSWORD"

		fi

		

	else

		echo "\nERROR: Private key file not found <$PRIVATE_KEY_FILE>"
		exit 1

   	fi

}

displayResult(){

		local PRIVATE_KEY_FILE_PEM="$1"
		local PUBLIC_KEY_FILE_PEM="$2"
		local CSR_FILE="$3"
		local CERT_FILE_PEM="$4"
		local PASSWORD="$5"


		echo -e "\nINFO: Display results"

		if [ -f "$PRIVATE_KEY_FILE_PEM" ] ; then 
			echo -e "\nINFO:\t\tDisplay private key <$PRIVATE_KEY_FILE_PEM>\n"
			showPrivateKey "$PRIVATE_KEY_FILE_PEM" "$PASSWORD"
			echo -e "\n"
		fi

		if [ -f "$PUBLIC_KEY_FILE_PEM" ] ; then 
			echo -e "\nINFO:\t\tDisplay public key <$PUBLIC_KEY_FILE_PEM>\n"
			showPublicKey "$PUBLIC_KEY_FILE_PEM"
			echo -e "\n"
		fi

		if [ -f "$CSR_FILE" ] ; then 
			echo -e "\nINFO:\t\tDisplay CSR <$CSR_FILE>\n"
			showCsr "$CSR_FILE"
			echo -e "\n"
		fi


		if [ -f "$CA_CERT_FILE_PEM" ] ; then 
			echo -e "\nINFO:\t\tDisplay cert <$CERT_FILE_PEM>\n"
			showCert "$CA_CERT_FILE_PEM"
			echo -e "\n"
		fi

}


combineCertWithPrivateKey(){

	local ORDER="$1"

	local PRIVATE_KEY_FILE="$2"
	local CERTIFICATE_FILE="$3"
	local COMBINED_FILE="$4"
	local PASSWORD="$5"

	echo -e "INFO:\t\tPrivate Key: <$PRIVATE_KEY_FILE>"
	echo -e "INFO:\t\tCertificate File: <$CERTIFICATE_FILE>"
	echo -e "INFO:\t\tCombined File: <$COMBINED_FILE>"



	if ([ -f "$PRIVATE_KEY_FILE" ] && [ -f "$PRIVATE_KEY_FILE" ]  && ([ ! -f "$COMBINED_FILE" ] || $FILE_OVERWRITE)) ; then 


		if [[ "$ORDER" = "keyfirst" ]] ; then

			openssl rsa -in "$PRIVATE_KEY_FILE" -passin "pass:$PASSWORD" > "$COMBINED_FILE"
			openssl x509 -in "$CERTIFICATE_FILE" >> "$COMBINED_FILE"

		elif [[ "$ORDER" = "certfirst" ]] ; then

			openssl x509 -in "$CERTIFICATE_FILE" > "$COMBINED_FILE"
			openssl rsa -in "$PRIVATE_KEY_FILE" -passin "pass:$PASSWORD" >> "$COMBINED_FILE"
			
		fi

		if [ ! -f "$COMBINED_FILE" ] ; then

			echo "ERROR: Creating combined $ORDER File <$COMBINED_FILE>"
			exit 1

	   	fi

	else

		echo "ERROR: Creating combined $ORDER File <$COMBINED_FILE>"
		exit 1

	fi

}



convertKeyCertToPkcs12 () {

	local KEY_FILE="$1"
	local CERT_FILE="$2"
	local PFX_FILE="$3"
	local PASSWORD="$4"

	echo -e "INFO:\t\tKey: <$KEY_FILE>"
	echo -e "INFO:\t\tCert: <$CERT_FILE>"
	echo -e "INFO:\t\tPFX: <$PFX_FILE>"

	if ([ -f "$PFX_FILE" ] && $FILE_BACKUP ) ; then 

		doBackup "$PFX_FILE"
    	
   	fi


   	if ([ -f "$KEY_FILE" ] && [ -f "$CERT_FILE" ] && ([ ! -f "$PFX_FILE" ] || $FILE_OVERWRITE)) ; then

		openssl pkcs12 -inkey "$KEY_FILE" -in "$CERT_FILE" -export -out "$PFX_FILE" -passin "pass:$PASSWORD" -passout "pass:$PASSWORD" &>/dev/null

		if [ -f "$PFX_FILE" ] ; then 

			echo "INFO: PFX Container created <$PFX_FILE>"



		else

			echo "ERROR: Creating PFX Container <$PFX_FILE>"
			exit 1
    	
   		fi

	else

		echo "ERROR: Creating PFX Container $PFX_FILE"
		exit 1
	fi

}


convertCertsToPkcs7 () {

	if [ $# -ge 2 ] ; then

		local P7B_FILE="$1"

		echo -e "INFO:\t\tP7B File: <$P7B_FILE>"

		if ([ -f "$P7B_FILE" ] && $FILE_BACKUP ) ; then 

			doBackup "$P7B_FILE"
	    	
	   	fi


		local CERT_STRING=""

		for ((i = 2; i <= $#; i++ )); do
		 
			echo -e "INFO:\t\tCert $i: <${!i}>"

			if [ ! -f "${!i}" ] ; then 

				echo "ERROR: Input file not found ${!i}"
				exit 1 
    	
			else 

				CERT_STRING+=" -certfile ${!i}"
   			
   			fi

		done


	   	if ([ ! -f "$P7B_FILE" ] || $FILE_OVERWRITE) ; then

	   		local COMMAND="openssl crl2pkcs7 -nocrl $CERT_STRING -out $P7B_FILE"

	   		eval "$COMMAND"

			if [ -f "$P7B_FILE" ] ; then 

				echo "INFO: P7B Container created <$P7B_FILE>"

			else

				echo "ERROR: Creating P7B Container <$P7B_FILE>"
				exit 1
	    	
	   		fi

		else

			echo "ERROR: Creating P7B Container $P7B_FILE"
			exit 1
		fi
    
    else

	   echo "ERROR: Provide p7b output file and at least one certificate"
	   exit 1
	
	fi

}


convertKeyToDer() {

	local PEM_KEY="$1"
	local DER_KEY="$2"
	local PASSWORD="$3"

	echo -e "INFO:\t\tPEM: <$PEM_KEY>"
	echo -e "INFO:\t\tDER: <$DER_KEY>"


	if ([ -f "$DER_KEY" ] && $FILE_BACKUP ) ; then 

		doBackup "$DER_KEY"
    	
   	fi


   	if ([ -f "$PEM_KEY" ] && ([ ! -f "$DER_KEY" ] || $FILE_OVERWRITE)) ; then


	   	if [[ "$#" = 2 ]]; then

 			openssl rsa -pubin -inform PEM -in "$PEM_KEY" -outform DER -out "$DER_KEY" &>/dev/null

		elif [[ "$#" = 3 ]]; then

			openssl rsa -in "$PEM_KEY" -pubout -outform DER -out "$DER_KEY" -passin "pass:$PASSWORD" &>/dev/null
		
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

	echo -e "INFO:\t\tPEM: <$PEM_CERT>"
	echo -e "INFO:\t\tDER: <$DER_CERT>"

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

	echo -e "INFO:\t\tPEM: <$PEM_CRL>"
	echo -e "INFO:\t\tDER: <$DER_CRL>"

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




createDbFile() {

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


createCrlPemFile() {

	local CA_SSL_CONFIG_FILE="$1"
	local CA_CRL_FILE="$2"
	local PASSWORD="$3"

	if ([ -f "$CA_CRL_FILE" ] && $FILE_BACKUP ) ; then 

		doBackup "$CA_CRL_FILE"
    	
   	fi

   	if ([ ! -f "$CA_CRL_FILE" ] || $FILE_OVERWRITE ) ; then

   		openssl ca -config "$CA_SSL_CONFIG_FILE" \
   		-crlexts crl_ext \
     	-gencrl -out "$CA_CRL_FILE" \
     	-passin "pass:$PASSWORD" \
     	&>/dev/null


     	if ([ ! -f "$CA_CRL_FILE" ]) ; then

   			echo "\nERROR: Can not create Crl PEM file $CA_CRL_FILE"
   			exit 1

   		fi

   	else

   		echo "\nERROR: Can not create CRL PEM file $CA_CRL_FILE"

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

createRootCaPrivateKey() {
	
	local CA_PRIVATE_KEY_FILE="$1"
	local PASSWORD="$2"

	echo -e "INFO:\t\tKey: <$CA_PRIVATE_KEY_FILE>"
	echo -e "INFO:\t\tBits: <$CA_KEY_BITS>"
	echo -e "INFO:\t\tKey Algo: <$CA_KEY_ALGO>"

	if ([ -f "$CA_PRIVATE_KEY_FILE" ] && $FILE_BACKUP ) ; then 

		doBackup "$CA_PRIVATE_KEY_FILE"
    	
   	fi


	if ([ ! -f "$CA_PRIVATE_KEY_FILE" ] || $FILE_OVERWRITE ) ; then

		openssl genpkey \
				-algorithm rsa \
				-out $CA_PRIVATE_KEY_FILE \
				-$CA_KEY_ALGO -pkeyopt rsa_keygen_bits:$CA_KEY_BITS \
				-pass stdin <<<"$PASSWORD" \
				&>/dev/null

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

createPublicKey() {

	local PRIVATE_KEY_FILE="$1"
	local PUBLIC_KEY_FILE="$2"
	local PASSWORD="$3"

	echo -e "INFO:\t\tPrivate Key: <$PRIVATE_KEY_FILE>"
	echo -e "INFO:\t\tPublic Key: <$PUBLIC_KEY_FILE>"


	if ([ -f "$PUBLIC_KEY_FILE" ] && $FILE_BACKUP ) ; then 

		doBackup "$PUBLIC_KEY_FILE"
    	
   	fi

   	if ([ -f "$PRIVATE_KEY_FILE" ] && ([ ! -f "$PUBLIC_KEY_FILE" ] || $FILE_OVERWRITE ))  ; then

		openssl rsa -in "$PRIVATE_KEY_FILE" \
				-pubout \
				-out "$PUBLIC_KEY_FILE" \
				-passin "pass:$PASSWORD" \
				&>/dev/null

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

sslConfigDistributionPointsBlock(){

	local CA_FQDN="$1"

read -d '' CONFIG_PART <<END
#######

[crl_dist_sect] 
URI.1 = http://$CA_FQDN/ca/public/$CA_FQDN.der.crl

 #######

END

	echo "$CONFIG_PART"

}

sslConfigAiaBlock(){

	local CA_FQDN="$1"

read -d '' CONFIG_PART <<END
#######

[aia_sect] 
OCSP;URI.1=http://$CA_FQDN/
caIssuers;URI.2=http://$CA_FQDN/ca/public/$CA_FQDN.der.cer

#caIssuers;URI.3=ldap://server.whatever.org/xxx,yyy 

 #######

END

	echo "$CONFIG_PART"

}

sslConfigReqBlock(){

	local CA_KEY_BITS="$1"
	local CA_HASH_ALGO="$2"
	
read -d '' CONFIG_PART <<END
####### req

[ req ]
default_bits        = $CA_KEY_BITS
distinguished_name  = req_distinguished_name
string_mask         = utf8only
utf8                = yes
default_md          = $CA_HASH_ALGO
encrypt_key         = yes
prompt              = no
x509_extensions     = v3_ca

 #######

END

	echo "$CONFIG_PART"

}

sslConfigReqDnBlock(){


	local C="$1"
	local O="$2"
	local OU="$3"
	local ST="$4"
	local L="$5"

read -d '' CONFIG_PART <<END
####### req_distinguished_name

[ req_distinguished_name ]
countryName             = $C
organizationName        = $O
organizationalUnitName  = $OU
stateOrProvinceName     = $ST
localityName            = $L

#countryName_default             = $C
#stateOrProvinceName_default     = $ST
#localityName_default            = $L
#0.organizationName_default      = $O
#organizationalUnitName_default  = $OU
#emailAddress_default            =


 #######

END

	echo "$CONFIG_PART"

}


sslConfigUserCertBlock(){

	local CA_FQDN="$1"

read -d '' CONFIG_PART <<END
####### usr_cert

[ usr_cert ]
basicConstraints = CA:FALSE
nsCertType = client, email
nsComment = "$CA_FQDN - Client Certificate"
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
keyUsage = critical, nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth, emailProtection
authorityInfoAccess = @aia_sect
crlDistributionPoints = @crl_dist_sect

 #######

END

	echo "$CONFIG_PART"

}

sslConfigServerCertBlock(){

	local CA_FQDN="$1"

read -d '' CONFIG_PART <<END
####### server_cert

[ server_cert ]
basicConstraints = CA:FALSE
nsCertType = server
nsComment = "$CA_FQDN - Server Certificate"
subjectKeyIdentifier = hash
#authorityKeyIdentifier = keyid,issuer:always
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
authorityInfoAccess = @aia_sect
crlDistributionPoints = @crl_dist_sect
subjectAltName                  = @alt_names

 #######

END

	echo "$CONFIG_PART"

}


sslConfigV3CaBlock(){

	local CA_FQDN="$1"

read -d '' CONFIG_PART <<END
####### v3_ca

[ v3_ca ]
subjectKeyIdentifier = hash
basicConstraints = critical, CA:true
keyUsage = critical, digitalSignature, cRLSign, keyCertSign
nsComment = "$CA_FQDN - CA Certificate"

 #######

END

	echo "$CONFIG_PART"

}



sslConfigV3IntermediateCaBlock(){

	local CA_FQDN="$1"

read -d '' CONFIG_PART <<END
####### v3_intermediate_ca

[ v3_intermediate_ca ]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer:always
basicConstraints = critical, CA:true, pathlen:0
keyUsage = critical, digitalSignature, cRLSign, keyCertSign
nsComment = "$CA_FQDN - Intermediate CA Certificate"
authorityInfoAccess = @aia_sect
crlDistributionPoints = @crl_dist_sect

 #######

END

	echo "$CONFIG_PART"

}



sslConfigCaBlock(){

read -d '' CONFIG_PART <<END
####### ca

[ ca ]
default_ca              = CA_default               # The default CA section

 #######

END

	echo "$CONFIG_PART"

}

sslConfigCaDefaultBlock(){

	local CA_FQDN="$1"
	local CA_DEFAULT_DAYS="$2"
	local CA_DEFAULT_CRL_DAYS="$3"

	local CA_CERT_FILE=$(getSubfolderPath "$CA_FQDN" "ca" "public" "cert" "PEM")
	local CA_KEY_FILE=$(getSubfolderPath "$CA_FQDN" "ca" "private" "key" "PEM") 
	local CA_CRL_NUMBER_FILE=$(getSubfolderPath "$CA_FQDN" "ca" "private" "crl" "TXT") 
	local CA_CRL_FILE=$(getSubfolderPath "$CA_FQDN" "ca" "public" "crl" "PEM") 
	local CA_SERIAL_FILE=$(getSubfolderPath "$CA_FQDN" "ca" "database" "serial" "SRL") 
	local CA_INDEX_FILE=$(getSubfolderPath "$CA_FQDN" "ca" "database" "database" "DB") 
	local CA_RANDOM_FILE=$(getSubfolderPath "$CA_FQDN" "ca" "private" "randomfile" "RND") 


read -d '' CONFIG_PART <<END
####### CA_default

[ CA_default ]
# Directories
dir               = ./data/$CA_FQDN
crl_dir           = \$dir/ca/public/
new_certs_dir     = \$dir/ca/database/certs

# Files
database          = \$dir/$CA_INDEX_FILE
serial            = \$dir/$CA_SERIAL_FILE
RANDFILE          = \$dir/$CA_RANDOM_FILE
private_key       = \$dir/$CA_KEY_FILE
certificate       = \$dir/$CA_CERT_FILE
crlnumber         = \$dir/$CA_CRL_NUMBER_FILE
crl               = \$dir/$CA_CRL_FILE

default_md        = $CA_HASH_ALGO
default_days      = $CA_DEFAULT_DAYS
default_crl_days  = $CA_DEFAULT_CRL_DAYS

crl_extensions    = crl_ext
name_opt          = ca_default
cert_opt          = ca_default
policy            = policy_strict

preserve          = no
unique_subject    = no

base_url          = http://$CA_FQDN            # CA base URL
aia_url           = \$base_url/$CA_CERT_FILE   # CA certificate URL
crl_url           = \$base_url/$CA_CRL_FILE    # CRL distribution point
#name_opt         = multiline,-esc_msb,utf8    # Display UTF-8 characters

 #######

END

	echo "$CONFIG_PART"

}

sslConfigCapoliciesBlocks(){

read -d '' CONFIG_PART <<END
####### policies

[ policy_strict ]
countryName             = match
stateOrProvinceName     = match
organizationName        = match
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional

[ policy_loose ]
# Allow the intermediate CA to sign a more diverse range of certificates.
countryName             = optional
stateOrProvinceName     = optional
localityName            = optional
organizationName        = optional
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional

 #######

END

	echo "$CONFIG_PART"


}


sslConfigCrlExtBlock(){

	local CA_FQDN="$1"

read -d '' CONFIG_PART <<END
####### crl_ext

[ crl_ext ]
authorityInfoAccess = @aia_sect
crlDistributionPoints = @crl_dist_sect

 #######
END

	echo "$CONFIG_PART"

}


sslConfigOcspBlock(){

read -d '' CONFIG_PART <<END
####### ocsp

[ ocsp ]
basicConstraints = CA:FALSE
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
keyUsage = critical, digitalSignature
extendedKeyUsage = critical, OCSPSigning

END

	echo "$CONFIG_PART"

}

####### END OPENSSL #####

createOpenSslConfig (){

	CONFIG_FILE="$1"
	C="$2"
	ST="$3"
	L="$4"
	O="$5"
	OU="$6"
	CA_FQDN="$7"

	echo -e "INFO: \t\t CA Config File: <$CONFIG_FILE>"
	echo -e "INFO: \t\t CA Country: <$C>"
	echo -e "INFO: \t\t CA State: <$ST>"
	echo -e "INFO: \t\t CA Locality: <$L>"
	echo -e "INFO: \t\t CA Organisation: <$O>"
	echo -e "INFO: \t\t CA Organisation Unit: <$OU>"
	echo -e "INFO: \t\t CA FQDN: <$CA_FQDN>"

	if ([ -f "$CONFIG_FILE" ] && $FILE_BACKUP ) ; then 

		doBackup "$CONFIG_FILE"
    	
   	fi

   	if ( [ ! -f "$CONFIG_FILE" ] || $FILE_OVERWRITE )  ; then

   			SSL_CONFIG_AIA_BLOCK=$(sslConfigAiaBlock "$CA_FQDN")
   			SSL_CONFIG_DISTP_BLOCK=$(sslConfigDistributionPointsBlock "$CA_FQDN")
			SSL_CONFIG_CA_BLOCK=$(sslConfigCaBlock)
			SSL_CONFIG_CA_DEFAULT_BLOCK=$(sslConfigCaDefaultBlock "$CA_FQDN" "$HOST_CERT_EXPIRE_DAYS" "$CA_CRL_DAYS" )
			SSL_CONFIG_CA_POLICIES_BLOCK=$(sslConfigCapoliciesBlocks)
			SSL_CONFIG_REQ_BLOCK=$(sslConfigReqBlock "$CA_KEY_BITS" "$CA_HASH_ALGO")
			SSL_CONFIG_REQ_DN_BLOCK=$(sslConfigReqDnBlock "$C" "$O" "$OU" "$ST" "$L")
			SSL_CONFIG_V3_CA_BLOCK=$(sslConfigV3CaBlock "$CA_FQDN")	
			SSL_CONFIG_V3_INTER_CA_BLOCK=$(sslConfigV3IntermediateCaBlock "$CA_FQDN")
			SSL_CONFIG_USER_CERT_BLOCK=$(sslConfigUserCertBlock "$CA_FQDN")
			SSL_CONFIG_SERVER_CERT_BLOCK=$(sslConfigServerCertBlock "$CA_FQDN")
			SSL_CONFIG_CRL_EXT_BLOCK=$(sslConfigCrlExtBlock "$CA_FQDN")
			SSL_CONFIG_OCSP_BLOCK=$(sslConfigOcspBlock)
	
			OUTPUT=""
			OUTPUT+="$SSL_CONFIG_AIA_BLOCK"
			OUTPUT+="$SSL_CONFIG_DISTP_BLOCK"
			OUTPUT+="$SSL_CONFIG_CA_BLOCK"
			OUTPUT+="$SSL_CONFIG_CA_DEFAULT_BLOCK"
			OUTPUT+="$SSL_CONFIG_CA_POLICIES_BLOCK"
			OUTPUT+="$SSL_CONFIG_REQ_BLOCK"
			OUTPUT+="$SSL_CONFIG_REQ_DN_BLOCK"
			OUTPUT+="$SSL_CONFIG_V3_CA_BLOCK"
			OUTPUT+="$SSL_CONFIG_V3_INTER_CA_BLOCK"
			OUTPUT+="$SSL_CONFIG_USER_CERT_BLOCK"
			OUTPUT+="$SSL_CONFIG_SERVER_CERT_BLOCK"
			OUTPUT+="$SSL_CONFIG_CRL_EXT_BLOCK"

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

selfSignCsr() {

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
		    -notext \
			-days "$CA_CERT_EXPIRE_DAYS" \
			-subj "$CA_CSR_SUBJECT_LINE" \
			-passin "pass:$PASSWORD" \
		    -config "$CA_SSL_CONFIG_FILE" &>/dev/null

		if [ -f "$CA_CERT_FILE" ] ; then 

			echo "INFO: Created CA root cert <$CA_CERT_FILE>"

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

	echo -e "\nINFO: Cleaning Folder <$PARENT_FOLDER>"

	for OLD_FILE in $PARENT_FOLDER/*.old
	do

	    if [ -f "${OLD_FILE}" ]; then
	   
	    echo -e "INFO: \t\tDeleting <$OLD_FILE>";
	    rm $OLD_FILE

	    fi

	done

	echo -e "INFO: Folder cleaned <$PARENT_FOLDER>"

}

createCsr() {

	local REQ_EXTS="$1"
	local CA_SSL_CONFIG_FILE="$2"
	local KEY_FILE="$3"
	local CSR_FILE="$4"	
	local CSR_SUBJECT_LINE="$5"	
	local CERT_EXPIRE_DAYS="$6"
	local SAN_LINE="$7"
	local PASSWORD="$8"

	echo -e "INFO:\t\tSSL Extension: <$REQ_EXTS>"
	echo -e "INFO:\t\tSSL Config: <$CA_SSL_CONFIG_FILE>"
	echo -e "INFO:\t\tKey: <$KEY_FILE>"
	echo -e "INFO:\t\tCSR: <$CSR_FILE>"
	echo -e "INFO:\t\tSubject: <$CSR_SUBJECT_LINE>"
	echo -e "INFO:\t\tExpire Days: <$CERT_EXPIRE_DAYS>"
	echo -e "INFO:\t\tSAN: <$SAN_LINE>"
	
	if ([ -f "$CA_CSR_FILE" ] && $FILE_BACKUP ) ; then 

		doBackup "$CA_CSR_FILE"
    	
   	fi

	if ([ -f "$KEY_FILE" ] && ([ ! -f "$CSR_FILE" ] || $FILE_OVERWRITE ))  ; then

			INDEX=0
			RAW_VALUE=""
	
			SAN_BLOCK=""
			export IFS=","

			for SAN_ENTRY in $SAN_LINE; do

				INDEX=$(($INDEX+1))


				if [[ "$SAN_ENTRY" =~ IP:* ]] ; then

					RAW_VALUE="${SAN_ENTRY/IP\:/}\n"

					SANBLOCK+="IP.$INDEX = $RAW_VALUE"

				elif [[ "$SAN_ENTRY" =~ DNS:* ]]; then

					RAW_VALUE="${SAN_ENTRY/DNS\:/}\n"

					SANBLOCK+="DNS.$INDEX = $RAW_VALUE"

				else 

					continue

				fi
				
			done

			openssl req -new -key "$KEY_FILE" \
					-subj "$CSR_SUBJECT_LINE" \
					-days "$CERT_EXPIRE_DAYS" \
					-out "$CSR_FILE" \
					-passin "pass:$PASSWORD" \
					-reqexts "$REQ_EXTS" \
		     		-config <(cat "$CA_SSL_CONFIG_FILE" \
		       		<(printf "\n[alt_names]\n$SANBLOCK\n")) \
           		    -out "$CSR_FILE" 


		if [ -f "$CSR_FILE" ] ; then 

			echo "INFO: Created CSR <$CSR_FILE>"

		else

			echo "ERROR: Creating CSR <$CSR_FILE>"
			exit 1
    	
   		fi


	else

		echo "ERROR: Creating $CSR_FILE"
		exit 1

	fi	

}

signCsr() {

	local CA_EXT="$1"
	local CA_SSL_CONFIG_FILE="$2"
	local SUBJECT="$3"
	local SAN_LINE="$4"
	local CSR_FILE="$5"	
	local CERT_FILE="$6"
	local PASSWORD="$7"

	echo -e "INFO: \t\t SSL Config: <$CA_SSL_CONFIG_FILE>"
	echo -e "INFO: \t\t Subject: <$SUBJECT>"
	echo -e "INFO: \t\t SAN Line: <$SAN_LINE>"
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

   			SAN_BLOCK=""
			export IFS=","
			INDEX=0

			for SAN_LINE in $SAN_LINE; do

				INDEX=$(($INDEX+1))
				SAN_ENTRY="${SAN_LINE/\:/=}\n"
				SANBLOCK+=$SAN_ENTRY

			done

		   	openssl ca \
		   	-batch \
		    -in "$CSR_FILE" \
		    -out "$CERT_FILE" \
		    -notext \
		    -passin "pass:$PASSWORD" \
		    -subj "$SUBJECT" \
		    -extensions "$CA_EXT" \
     		-config <(cat "$CA_SSL_CONFIG_FILE" \
       		<(printf "\n[alt_names]\n$SANBLOCK\n")) \
       		&>/dev/null

			if [ -f "$CERT_FILE" ] ; then 

				echo "INFO: Created cert <$CERT_FILE>"

			else

				echo "ERROR: Creating cert <$CERT_FILE>"
				exit 1
	    	
	   		fi

		fi

	else

		echo "ERROR: Can not create cert $CERT_FILE"

	fi

}

##### Host Related

createHostPrivateKey() {
	
	local HOST_PRIVATE_KEY_FILE="$1"
	local PASSWORD="$2"

	echo -e "INFO:\t\tKey: <$HOST_PRIVATE_KEY_FILE>"
	echo -e "INFO:\t\tBits: <$HOST_KEY_BITS>"

	if ([ -f "$HOST_PRIVATE_KEY_FILE" ] && $FILE_BACKUP ) ; then 

		doBackup "$HOST_PRIVATE_KEY_FILE"
    	
   	fi

	if ([ ! -f "$HOST_PRIVATE_KEY_FILE" ] || $FILE_OVERWRITE ) ; then

		openssl genrsa  -out "$HOST_PRIVATE_KEY_FILE" -passout "pass:$PASSWORD" &>/dev/null

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
  <title>$CA_NAME - Certificate authority</title>
 <!-- <LINK href="styles.css" rel="stylesheet" type="text/css"> -->
</head>

<body>

<p>
<h1>Certificate authority</h1>
<h2>$CA_NAME</h2>
This is the Web Touchpoint of $CA_NAME Certificate authority
</br>
</br>
<h3>Main Data</h3>
<a href="$CA_PUBLIC_CERT">CA Certificate</a>
</br>
<a href="$CA_CRL">CA Certificate Revocation List</a>
</br>
</br>
<h3>Data Browser</h3>
<a href="ca/public/">Public CA data</a>
</br>
<a href="hosts/public/">Public Host data</a>
</p>

</body>
</html>
END

	echo -e "$HTML_PAGE" > "$HTML_FILE"
	
	if [ -f "$HTML_FILE" ] ; then 

		echo "INFO: Created HTML <$HTML_FILE>"

	else

		echo "ERROR: Creating HTML <$HTML_FILE>"
		exit 1
	
	fi

}

##################################################### 

createCA() {

	local ROOT_FOLDER="$1"
	local CC="$2"
	local ST="$3"
	local L="$4"
	local O="$5"
	local OU="$6"
	local CA_FQDN="$7"

	
	local CA_FOLDER=$(getCaFolder "$ROOT_FOLDER" "$CA_FQDN")

	echo -e "\nINFO: Creating CA <$CA_FQDN> into <$CA_FOLDER>"


	if ([ -d "$CA_FOLDER" ] && $FILE_BACKUP ) ; then 

		echo -e "\nINFO: Creating Backup for CA <$CA_FOLDER>"
		doBackup "$CA_FOLDER"
    	
   	fi

   	if ([ ! -d "$CA_FOLDER" ] || $FILE_OVERWRITE )  ; then

		createCaFolders "$CA_FOLDER"

   		local CA_SERIAL_FILE=$(getFilePath "$ROOT_FOLDER" "$CA_FQDN" "$CA_FQDN" "ca" "database" "serial" "SRL") 
   		local CA_DATABASE_FILE=$(getFilePath "$ROOT_FOLDER" "$CA_FQDN" "$CA_FQDN" "ca" "database" "database" "DB") 
   		local CA_CRL_NUMBER_FILE_TXT=$(getFilePath "$ROOT_FOLDER" "$CA_FQDN" "$CA_FQDN" "ca" "private" "crl" "TXT") 
		local CA_CRL_FILE_PEM=$(getFilePath "$ROOT_FOLDER" "$CA_FQDN" "$CA_FQDN" "ca" "public" "crl" "PEM") 
		local CA_CRL_FILE_DER=$(getFilePath "$ROOT_FOLDER" "$CA_FQDN" "$CA_FQDN" "ca" "public" "crl" "DER") 
   		local CA_SSL_CONFIG_FILE=$(getFilePath "$ROOT_FOLDER" "$CA_FQDN" "$CA_FQDN" "ca" "config" "sslconfig" "SSLCONFIG") 
   		local CA_HTML_INDEX_FILE=$(getFilePath "$ROOT_FOLDER" "$CA_FQDN" "$CA_FQDN" "ca" "wwwroot" "indexhtml" "HTML") 
		local CA_PRIVATE_KEY_FILE_PEM=$(getFilePath "$ROOT_FOLDER" "$CA_FQDN" "$CA_FQDN" "ca" "private" "key" "PEM") 
		local CA_PRIVATE_KEY_FILE_DER=$(getFilePath "$ROOT_FOLDER" "$CA_FQDN" "$CA_FQDN" "ca" "private" "key" "DER") 
		local CA_PUBLIC_KEY_FILE_PEM=$(getFilePath "$ROOT_FOLDER" "$CA_FQDN" "$CA_FQDN" "ca" "public" "key" "PEM")
		local CA_PUBLIC_KEY_FILE_DER=$(getFilePath "$ROOT_FOLDER" "$CA_FQDN" "$CA_FQDN" "ca" "public" "key" "DER")
		local CA_CERT_CSR_FILE=$(getFilePath "$ROOT_FOLDER" "$CA_FQDN" "$CA_FQDN" "ca" "public" "csr" "PEM")
		local CA_CERT_FILE_PEM=$(getFilePath "$ROOT_FOLDER" "$CA_FQDN" "$CA_FQDN" "ca" "public" "cert" "PEM")
		local CA_CERT_FILE_DER=$(getFilePath "$ROOT_FOLDER" "$CA_FQDN" "$CA_FQDN" "ca" "public" "cert" "DER")
		local CA_CERT_FILE_DER_RELATIVE=$(getSubfolderPath "$CA_FQDN" "ca" "public" "cert" "DER")
		local CA_CRL_FILE_DER_RELATIVE=$(getSubfolderPath "$CA_FQDN" "ca" "public" "crl" "DER") 

		local CA_CERT_SUBJECT_LINE=$(generateCertSubjectLine "$CC" "$ST" "$L" "$O" "$OU" "$CA_FQDN")
		local CA_SAN_LINE="DNS:$CA_FQDN"

		echo -e "\nINFO: Creating CA OpenSSL config File <$CA_SSL_CONFIG_FILE>"
		createOpenSslConfig "$CA_SSL_CONFIG_FILE" "$CC" "$ST" "$L" "$O" "$OU" "$CA_FQDN"

		echo -e "\nINFO: Creating CA serial file <$CA_SERIAL_FILE>"
		createSerialFile "$CA_SERIAL_FILE"

		echo -e "\nINFO: Creating CA CRL Number file <$CA_CRL_NUMBER_FILE_TXT>"
		createCrlFile "$CA_CRL_NUMBER_FILE_TXT"

		echo -e "\nINFO: Creating CA database file <$CA_DATABASE_FILE>"
		createDbFile "$CA_DATABASE_FILE"

		
		echo -e "\nINFO: Setting RSA Key passwords"
		local ROOT_KEY_PASSWORD=$(readPasswordInput "Please enter password for new CA private key")

		echo -e "\nINFO: Creating CA private key PEM <$CA_PRIVATE_KEY_FILE_PEM>"
		createRootCaPrivateKey "$CA_PRIVATE_KEY_FILE_PEM" "$ROOT_KEY_PASSWORD"

		echo -e "\nINFO: Creating CA private key DER <$CA_PRIVATE_KEY_FILE_DER>"
		convertKeyToDer "$CA_PRIVATE_KEY_FILE_PEM" "$CA_PRIVATE_KEY_FILE_DER" "$ROOT_KEY_PASSWORD"

		echo -e "\nINFO: Creating CA public key PEM <$CA_PUBLIC_KEY_FILE_PEM>"
		createPublicKey "$CA_PRIVATE_KEY_FILE_PEM" "$CA_PUBLIC_KEY_FILE_PEM" "$ROOT_KEY_PASSWORD"
		
		echo -e "\nINFO: Creating CA public key DER <$CA_PUBLIC_KEY_FILE_DER>"
		convertKeyToDer "$CA_PUBLIC_KEY_FILE_PEM" "$CA_PUBLIC_KEY_FILE_DER"

		echo -e "\nINFO: Creating CA CSR <$CA_CERT_CSR_FILE>"
		createCsr "v3_ca" "$CA_SSL_CONFIG_FILE" "$CA_PRIVATE_KEY_FILE_PEM" "$CA_CERT_CSR_FILE" "$CA_CERT_SUBJECT_LINE" "$CA_CERT_EXPIRE_DAYS" "$CA_SAN_LINE" "$ROOT_KEY_PASSWORD"

		echo -e "\nINFO: Creating CA root cert PEM <$CA_CERT_FILE_PEM>"
		selfSignCsr "$CA_SSL_CONFIG_FILE" "$CA_CERT_CSR_FILE" "$CA_CERT_FILE_PEM" "$CA_CERT_SUBJECT_LINE" "$ROOT_KEY_PASSWORD"
		cleanUpDotOldFiles "$CA_DATABASE_FILE"

		echo -e "\nINFO: Creating CA root cert DER <$CA_CERT_FILE_DER>"
		convertCertToDer "$CA_CERT_FILE_PEM" "$CA_CERT_FILE_DER"

		echo -e "\nINFO: Creating CA Certificate revocation file PEM <$CA_CRL_FILE_PEM>"
		createCrlPemFile "$CA_SSL_CONFIG_FILE" "$CA_CRL_FILE_PEM" "$ROOT_KEY_PASSWORD"
		cleanUpDotOldFiles "$CA_CRL_NUMBER_FILE_TXT"

		echo -e "\nINFO: Creating CA Certificate revocation file DER <$CA_CRL_FILE_DER>"
		convertCrlToDer "$CA_CRL_FILE_PEM" "$CA_CRL_FILE_DER" 

		echo -e "\nINFO: Creating HTML <$CA_HTML_INDEX_FILE>"
		createIndexHtml "$CA_FQDN" "$CA_HTML_INDEX_FILE" "$CA_CERT_FILE_DER_RELATIVE" "$CA_CRL_FILE_DER_RELATIVE"

		displayResult "$CA_PRIVATE_KEY_FILE_PEM" "$CA_PUBLIC_KEY_FILE_PEM" "$CA_CERT_CSR_FILE" "$CA_CERT_FILE_PEM" "$ROOT_KEY_PASSWORD"
		
		# RESETTING VARIABLES
		ROOT_KEY_PASSWORD=""
		SIGNING_KEY_PASSWORD=""

	else

		echo "ERROR Creating CA $CN in Folder $CA_FOLDER"
		exit 1

	fi

}

##################################################### 

createHost() {

	local ROOT_FOLDER="$1"
	local CC="$2"
	local ST="$3"
	local L="$4"
	local O="$5"
	local OU="$6"
	local P_SUBJECT="$7"
	local CA=$8
	local HOST_CERT_SAN_CONTENT="$9" 

	local CA_FOLDER=$(getCaFolder "$ROOT_FOLDER" "$CA")
	local HOST_CERT_SUBJECT_LINE=$(generateCertSubjectLine "$CC" "$ST" "$L" "$O" "$OU" "$P_SUBJECT")

	echo -e "\nINFO: Creating Host <$P_SUBJECT> via CA <$CA>"
	echo -e "INFO: \t\t Country: <$CC>"
	echo -e "INFO: \t\t State: <$ST>"
	echo -e "INFO: \t\t Location: <$L>"
	echo -e "INFO: \t\t Organisation key: <$O>"
	echo -e "INFO: \t\t Organisation unit: <$OU>"
	echo -e "INFO: \t\t Subject: <$P_SUBJECT>"
	echo -e "INFO: \t\t CA: <$CA>"
	echo -e "INFO: \t\t SAN Line: <$HOST_CERT_SAN_CONTENT>"

	local CA_SSL_CONFIG_FILE=$(getFilePath "$ROOT_FOLDER" "$CA" "$CA" "ca" "config" "sslconfig" "SSLCONFIG") 
	local CA_DATABASE_FILE=$(getFilePath "$ROOT_FOLDER" "$CA" "$CA" "ca" "database" "database" "DB") 
	local CA_CERT_FILE_PEM=$(getFilePath "$ROOT_FOLDER" "$CA" "$CA" "ca" "public" "cert" "PEM")

	local HOST_PRIVATE_KEY_FILE_PEM=$(getFilePath "$ROOT_FOLDER" "$CA" "$P_SUBJECT" "hosts" "private" "key" "PEM") 
	local HOST_PRIVATE_KEY_FILE_DER=$(getFilePath "$ROOT_FOLDER" "$CA" "$P_SUBJECT" "hosts" "private" "key" "DER") 

	local HOST_PUBLIC_KEY_FILE_PEM=$(getFilePath "$ROOT_FOLDER" "$CA" "$P_SUBJECT" "hosts" "public" "key" "PEM") 
	local HOST_PUBLIC_KEY_FILE_DER=$(getFilePath "$ROOT_FOLDER" "$CA" "$P_SUBJECT" "hosts" "public" "key" "DER") 
	
	local HOST_KEY_CSR_FILE=$(getFilePath "$ROOT_FOLDER" "$CA" "$P_SUBJECT" "hosts" "public" "csr" "PEM")

	local HOST_CERT_FILE_PEM=$(getFilePath "$ROOT_FOLDER" "$CA" "$P_SUBJECT" "hosts" "public" "cert" "PEM")
	local HOST_CERT_FILE_DER=$(getFilePath "$ROOT_FOLDER" "$CA" "$P_SUBJECT" "hosts" "public" "cert" "DER")

	local HOST_COMBINED_KEY_CERT_FILE=$(getFilePath "$ROOT_FOLDER" "$CA" "$P_SUBJECT" "hosts" "private" "keycert" "PEM")
	local HOST_COMBINED_CERT_KEY_FILE=$(getFilePath "$ROOT_FOLDER" "$CA" "$P_SUBJECT" "hosts" "private" "certkey" "PEM")
	local HOST_PFX_FILE=$(getFilePath "$ROOT_FOLDER" "$CA" "$P_SUBJECT" "hosts" "private" "pfx" "PFX")

	local HOST_P7B_FILE=$(getFilePath "$ROOT_FOLDER" "$CA" "$P_SUBJECT" "hosts" "public" "p7b" "P7B")

	##### FLOW 
	echo -e "\nINFO: Checking CA Folders in <$CA_FOLDER>"
	
	checkCaFolders "$CA_FOLDER"

	echo -e "\nINFO: Creating host subfolders>"

    createFolder "$CA_FOLDER/hosts/public/$P_SUBJECT"
	createFolder "$CA_FOLDER/hosts/private/$P_SUBJECT"
	
	echo -e "INFO: Host subfolders created>\n"

	local PRIVATE_KEY_PASSWORD=$(readPasswordInput "CA private key password")
    local HOST_KEY_PASSWORD=$(readPasswordInput "Host private key password")

	echo -e "\nINFO: Creating Host key PEM <$HOST_PRIVATE_KEY_FILE_PEM>"
	createHostPrivateKey "$HOST_PRIVATE_KEY_FILE_PEM" "$HOST_KEY_PASSWORD"

	echo -e "\nINFO: Creating Host key DER <$HOST_PRIVATE_KEY_FILE_DER>"
	convertKeyToDer "$HOST_PRIVATE_KEY_FILE_PEM" "$HOST_PRIVATE_KEY_FILE_DER" "$HOST_KEY_PASSWORD"

	echo -e "\nINFO: Creating Host public key PEM <$HOST_PUBLIC_KEY_FILE_PEM>"
	createPublicKey "$HOST_PRIVATE_KEY_FILE_PEM" "$HOST_PUBLIC_KEY_FILE_PEM" "$HOST_KEY_PASSWORD"

	echo -e "\nINFO: Creating Host public key DER <$HOST_PUBLIC_KEY_FILE_DER>"
	convertKeyToDer "$HOST_PUBLIC_KEY_FILE_PEM" "$HOST_PUBLIC_KEY_FILE_DER"

	echo -e "\nINFO: Creating CSR <$HOST_KEY_CSR_FILE>"
	createCsr "server_cert" "$CA_SSL_CONFIG_FILE" "$HOST_PRIVATE_KEY_FILE_PEM" "$HOST_KEY_CSR_FILE" "$HOST_CERT_SUBJECT_LINE" "$HOST_CERT_EXPIRE_DAYS" "$HOST_CERT_SAN_CONTENT" "$PRIVATE_KEY_PASSWORD" 

	echo -e "\nINFO: Creating PEM Host cert <$HOST_CERT_FILE_PEM>"
	signCsr "server_cert" "$CA_SSL_CONFIG_FILE" "$HOST_CERT_SUBJECT_LINE" "$HOST_CERT_SAN_CONTENT" "$HOST_KEY_CSR_FILE" "$HOST_CERT_FILE_PEM" "$PRIVATE_KEY_PASSWORD"
	cleanUpDotOldFiles "$CA_DATABASE_FILE"

	echo -e "\nINFO: Creating Host cert DER <$HOST_CERT_FILE_DER>"
	convertCertToDer "$HOST_CERT_FILE_PEM" "$HOST_CERT_FILE_DER"

	echo -e "\nINFO: Creating Host combined Private Key Cert File PEM <$HOST_COMBINED_KEY_CERT_FILE>"
	combineCertWithPrivateKey "keyfirst" "$HOST_PRIVATE_KEY_FILE_PEM" "$HOST_CERT_FILE_PEM" "$HOST_COMBINED_KEY_CERT_FILE" "$PRIVATE_KEY_PASSWORD"

	echo -e "\nINFO: Creating Host combined Private Cert Key File PEM <$HOST_COMBINED_CERT_KEY_FILE>"
	combineCertWithPrivateKey "certfirst" "$HOST_PRIVATE_KEY_FILE_PEM" "$HOST_CERT_FILE_PEM" "$HOST_COMBINED_CERT_KEY_FILE" "$PRIVATE_KEY_PASSWORD"

	echo -e "\nINFO: Creating Host combined Private Cert Key File PKCS12 PFX <$HOST_PFX_FILE>"
	convertKeyCertToPkcs12 "$HOST_PRIVATE_KEY_FILE_PEM" "$HOST_CERT_FILE_PEM" "$HOST_PFX_FILE" "$PRIVATE_KEY_PASSWORD"

	ROOT_KEY_PASSWORD=""
	SIGNING_KEY_PASSWORD=""

	echo -e "\nINFO: Creating Host combined Cert File PKCS7 P7B <$HOST_P7B_FILE>"
	convertCertsToPkcs7 "$HOST_P7B_FILE" "$CA_CERT_FILE_PEM" "$HOST_CERT_FILE_PEM"

#	displayResult "$HOST_PRIVATE_KEY_FILE_PEM" "$HOST_PUBLIC_KEY_FILE_PEM" "$HOST_KEY_CSR_FILE" "$HOST_CERT_FILE_PEM" "$PRIVATE_KEY_PASSWORD"
	


}

##################################################### 

revokeCertificate(){

	local ROOT_FOLDER="$1"
	local CA_FQDN="$2"
	local CN="$3"

	echo -e "INFO: \t\t Folder: <$ROOT_FOLDER>"
	echo -e "INFO: \t\t CA: <$CA_FQDN>"
	echo -e "INFO: \t\t Subject: <$CN>"

	local CA_CRL_FILE_PEM=$(getFilePath "$ROOT_FOLDER" "$CA_FQDN" "$CA_FQDN" "ca" "public" "crl" "PEM") 
	local CA_CRL_FILE_DER=$(getFilePath "$ROOT_FOLDER" "$CA_FQDN" "$CA_FQDN" "ca" "public" "crl" "DER") 
	local CA_CRL_FILE_TXT=$(getFilePath "$ROOT_FOLDER" "$CA_FQDN" "$CA_FQDN" "ca" "private" "crl" "TXT") 
	local CA_SSL_CONFIG_FILE=$(getFilePath "$ROOT_FOLDER" "$CA_FQDN" "$CA_FQDN" "ca" "config" "sslconfig" "SSLCONFIG") 
	local CA_PRIVATE_KEY_FILE_PEM=$(getFilePath "$ROOT_FOLDER" "$CN" "$CN" "ca" "private" "key" "PEM") 

	local HOST_CERT_FILE_PEM=$(getFilePath "$ROOT_FOLDER" "$CA_FQDN" "$CN" "hosts" "public" "cert" "PEM")

	echo -e "INFO: \t\t CA PEM CRL: <$CA_CRL_FILE_PEM>"
	echo -e "INFO: \t\t CA DER CRL: <$CA_CRL_FILE_DER>"
	echo -e "INFO: \t\t CA SSL Config: <$CA_SSL_CONFIG_FILE>"
	echo -e "INFO: \t\t CA Key: <$CA_PRIVATE_KEY_FILE_PEM>"
	echo -e "INFO: \t\t Cert to revoke: <$HOST_CERT_FILE_PEM>"

	echo -e "\nINFO: Enter RSA Key password:"
	local ROOT_KEY_PASSWORD=$(readPasswordInput "Please enter CA private key password")

	openssl ca -config "$CA_SSL_CONFIG_FILE" -revoke "$HOST_CERT_FILE_PEM" -passin "pass:$ROOT_KEY_PASSWORD"

	echo -e "\nINFO: Updating CA Certificate revocation file PEM <$CA_CRL_FILE_PEM>"
	createCrlPemFile "$CA_SSL_CONFIG_FILE" "$CA_CRL_FILE_PEM" "$ROOT_KEY_PASSWORD"
	cleanUpDotOldFiles "$CA_CRL_FILE_TXT"

	echo -e "\nINFO: Updating CA Certificate revocation file DER <$CA_CRL_FILE_DER>"
	convertCrlToDer "$CA_CRL_FILE_PEM" "$CA_CRL_FILE_DER" 

}


##################################################### START

P_MODE="$1"

if ([[ "$P_MODE" = "ca" ]] && [[ "$#" = 8 ]]); then

	P_ROOT_FOLDER="$2"
	P_CA_FQDN="$3"
	P_CC="$4"
	P_ST="$5"
	P_L="$6"
	P_O="$7"
	P_OU="$8"

	createCA "$P_ROOT_FOLDER" "$P_CC" "$P_ST" "$P_L" "$P_O" "$P_OU" "$P_CA_FQDN" 

elif ([[ "$P_MODE" = "host" ]] && [[ "$#" = 9 ]]); then

	P_ROOT_FOLDER="$2"
	P_CA_FQDN="$3"
	P_CC="$4"
	P_ST="$5"
	P_L="$6"
	P_O="$7"
	P_OU="$8"
	P_SAN="$9"

	P_SUBJECT=$(extractSubjectFromSan "$P_SAN")

	createHost "$P_ROOT_FOLDER" "$P_CC" "$P_ST" "$P_L" "$P_O" "$P_OU" "$P_SUBJECT" "$P_CA_FQDN" "$P_SAN"

elif ([[ "$P_MODE" = "revoke" ]] && [[ "$#" = 4 ]]); then

	P_ROOT_FOLDER="$2"
	P_CA_FQDN="$3"
	P_CN="$4"

	revokeCertificate "$P_ROOT_FOLDER" "$P_CA_FQDN" "$P_CN"

else

	echo "ERROR: Invalid arguments"
	printCmdInfo

fi
