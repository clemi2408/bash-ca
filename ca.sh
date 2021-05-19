#!/bin/bash

########
FILE_BACKUP=true
FILE_OVERWRITE=true
########
CA_KEY_BITS="4096"
CA_KEY_ALGO="AES-256-CBC"
CA_CERT_EXPIRE_DAYS="1825"
CA_HASH_ALGO="sha512"
########
HOST_KEY_BITS="2048"
HOST_CERT_EXPIRE_DAYS="1825"
HOST_HASH_ALGO="sha512"
#######
MIN_PASSWORD_LENGTH=4
MAX_PASSWORD_LENGTH=100
#######
declare -a CA_FOLDERS=("ca" "ca/public" "ca/private" "hosts" "hosts/public" "hosts/private")
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

			echo -e "ERROR: Invalid CA Folder structure"
			exit 1

		fi


	fi
}

getFileName() {

	local ROOT_FOLDER="$1"
	local CA="$2"
	local CN="$3"
	local TARGET="$4" # CA | HOST
	local VISIBILITY="$5" # public | private
	local FILE_TYPE="$6" # PRIVKEY | PUBKEY | CERT | SIGNKEY | SIGNCSR | SIGNCERT

	local CA_FOLDER=$(getCaFolder "$ROOT_FOLDER" "$CA")

	local TARGET_FILE_PREFIX="$CA_FOLDER/$TARGET/$VISIBILITY/$CN"


	if [ "$FILE_TYPE" = "PRIVKEY" ]; then

    	echo "$TARGET_FILE_PREFIX-private.key"

    elif [ "$FILE_TYPE" = "PUBKEY" ]; then

    	echo "$TARGET_FILE_PREFIX-public.key"

    elif [ "$FILE_TYPE" = "CERT" ]; then

    	echo "$TARGET_FILE_PREFIX.cert"

    elif [ "$FILE_TYPE" = "PRIVSIGNKEY" ]; then

    	echo "$TARGET_FILE_PREFIX-private-signing.key"
    
    elif [ "$FILE_TYPE" = "PUBSIGNKEY" ]; then

    	echo "$TARGET_FILE_PREFIX-public-signing.key"
        
    elif [ "$FILE_TYPE" = "SIGNCSR" ]; then

    	echo "$TARGET_FILE_PREFIX-signing.csr"

    elif [ "$FILE_TYPE" = "SIGNCERT" ]; then

    	echo "$TARGET_FILE_PREFIX-signing.cert"

    elif [ "$FILE_TYPE" = "CSR" ]; then

    	echo "$TARGET_FILE_PREFIX.csr"

    elif [ "$FILE_TYPE" = "SERIAL" ]; then

    	echo "$TARGET_FILE_PREFIX.srl"

	else

   		echo "\nERROR: File type <$FILE_TYPE> NOT KNOWN"
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
	echo -e "\t ./ca.sh host data_folder ca_fqdn CC ST L O OU Subject"
	echo -e "\t ./ca.sh host '/Users/clemens/Desktop/ownca/data' 'ca.int.cleem.de' 'DE' 'BW' 'Bruchsal' 'cleem.de' 'int.cleem.de' 'host01.static.int.cleem.de'"
	exit 1
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

##### CA Related

createSerialFile() {

	local SERIAL_FILE="$1"

	if ([ -f "$SERIAL_FILE" ] && $FILE_BACKUP ) ; then 

		doBackup "$SERIAL_FILE"
    	
   	fi

   	if ([ ! -f "$SERIAL_FILE" ] || $FILE_OVERWRITE ) ; then

   			echo "01" > "$SERIAL_FILE"

   	else

   		echo "\nERROR: Can not create serial file $SERIAL_FILE"

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

generateRootCaPublicKey() {

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

generateRootCaCert() {

	local CA_KEY_FILE="$1"
	local CA_CERT_FILE="$2"	
	local CA_CSR_SUBJECT_LINE="$3"	
	local PASSWORD="$4"


	echo -e "INFO: \t\t CA Key: <$CA_KEY_FILE>"
	echo -e "INFO: \t\t CA Cert: <$CA_CERT_FILE>"
	echo -e "INFO: \t\t Subject Line: <$CA_CSR_SUBJECT_LINE>"
	echo -e "INFO: \t\t Expiry: <$CA_CERT_EXPIRE_DAYS>"
	echo -e "INFO: \t\t Hash Algo: <$CA_HASH_ALGO>"


	if ([ -f "$CA_CERT_FILE" ] && $FILE_BACKUP ) ; then 

		doBackup "$CA_CERT_FILE"
    	
   	fi


	if ([ -f "$CA_KEY_FILE" ] && ([ ! -f "$CA_CERT_FILE" ] || $FILE_OVERWRITE ))  ; then


		openssl req -x509 -new -nodes \
					-key "$CA_KEY_FILE" \
					-"$CA_HASH_ALGO" \
					-days "$CA_CERT_EXPIRE_DAYS" \
					-out "$CA_CERT_FILE" \
					-subj "$CA_CSR_SUBJECT_LINE" \
					-passin "pass:$PASSWORD"



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

generateCsr() {

	local KEY_FILE="$1"
	local CSR_FILE="$2"	
	local CSR_SUBJECT_LINE="$3"	
	local CERT_EXPIRE_DAYS="$4"
	local HASH_ALGO="$5"
	local PASSWORD="$6"

	echo -e "INFO: \t\t Key: <$KEY_FILE>"
	echo -e "INFO: \t\t CSR: <$CSR_FILE>"
	echo -e "INFO: \t\t Subject: <$CSR_SUBJECT_LINE>"
	echo -e "INFO: \t\t Expire Days: <$CERT_EXPIRE_DAYS>"
	echo -e "INFO: \t\t Hash Algo: <$HASH_ALGO>"


	if ([ -f "$CA_CSR_FILE" ] && $FILE_BACKUP ) ; then 

		doBackup "$CA_CSR_FILE"
    	
   	fi


	if ([ -f "$KEY_FILE" ] && ([ ! -f "$CSR_FILE" ] || $FILE_OVERWRITE ))  ; then


		openssl req -new -key "$KEY_FILE" \
				-out "$CSR_FILE" \
				-days "$CERT_EXPIRE_DAYS" \
				-"$HASH_ALGO" \
				-subj "$CSR_SUBJECT_LINE" \
				-passin "pass:$PASSWORD"

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

	local CA_SERIAL_FILE="$1"
	local CSR_FILE="$2"	
	local CA_CERT="$3"
	local CA_KEY="$4"
	local CERT_FILE="$5"
	local CERT_EXPIRE_DAYS="$6"
	local HASH_ALGO="$7"
	local PASSWORD="$8"

	echo -e "INFO: \t\t CSR: <$CSR_FILE>"
	echo -e "INFO: \t\t Serial: <$CA_SERIAL_FILE>"
	echo -e "INFO: \t\t CA cert: <$CA_CERT>"
	echo -e "INFO: \t\t CA key: <$CA_KEY>"
	echo -e "INFO: \t\t Cert: <$CERT_FILE>"
	echo -e "INFO: \t\t Expiry: <$CERT_EXPIRE_DAYS>"
	echo -e "INFO: \t\t Hash Algo: <$HASH_ALGO>"


	if ([ -f "$CERT_FILE" ] && $FILE_BACKUP ) ; then 

		doBackup "$CERT_FILE"
    	
   	fi

   	if ([ ! -f "$CERT_FILE" ] || $FILE_OVERWRITE ) ; then

   		if ([ -f "$CSR_FILE" ] && [ -f "$CA_CERT" ] && [ -f "$CA_KEY" ] ) ; then


				openssl x509 -req -in "$CSR_FILE" \
							 -CA "$CA_CERT" \
							 -CAkey "$CA_KEY" \
							 -out "$CERT_FILE" \
							 -days "$CERT_EXPIRE_DAYS" \
							 -"$HASH_ALGO" \
							 -CAserial "$CA_SERIAL_FILE" \
							 -passin "pass:$PASSWORD"
							 #-CAcreateserial

			if [ -f "$CERT_FILE" ] ; then 

				echo "INFO: Created cert <$CERT_FILE>"

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

  
		createCaFolders "$CA_FOLDER"


   		local CA_SERIAL_FILE=$(getFileName "$ROOT_FOLDER" "$CN" "$CN" "ca" "private" "SERIAL") 
		local CA_PRIVATE_KEY_FILE=$(getFileName "$ROOT_FOLDER" "$CN" "$CN" "ca" "private" "PRIVKEY") 
		local CA_PUBLIC_KEY_FILE=$(getFileName "$ROOT_FOLDER" "$CN" "$CN" "ca" "public" "PUBKEY")
		local CA_CERT_FILE=$(getFileName "$ROOT_FOLDER" "$CN" "$CN" "ca" "public" "CERT")
		local CA_PRIVATE_SIGNING_KEY_FILE=$(getFileName "$ROOT_FOLDER" "$CN" "$CN" "ca" "private" "PRIVSIGNKEY")
		local CA_PUBLIC_SIGNING_KEY_FILE=$(getFileName "$ROOT_FOLDER" "$CN" "$CN" "ca" "public" "PUBSIGNKEY")


		local CA_SIGNING_KEY_CSR_FILE=$(getFileName "$ROOT_FOLDER" "$CN" "$CN" "ca" "private" "SIGNCSR")
		local CA_SIGNING_KEY_CERT_FILE=$(getFileName "$ROOT_FOLDER" "$CN" "$CN" "ca" "public" "SIGNCERT")

		local CA_CERT_SUBJECT_LINE=$(generateCertSubjectLine "$CC" "$ST" "$L" "$O" "$OU" "$CN")
		local CA_SINGN_KEY_CERT_SUBJECT_LINE=$(generateCertSubjectLine "$CC" "$ST" "$L" "$O" "$OU" "SignKey Cert $CN")


		echo -e "\nINFO: Creating CA serial file <$CA_SERIAL_FILE>"
		createSerialFile "$CA_SERIAL_FILE"

		echo -e "\nINFO: Setting RSA Key passwords"
		local ROOT_KEY_PASSWORD=$(readPasswordInput "CA private key password")
		local SIGNING_KEY_PASSWORD=$(readPasswordInput "CA signing key password")

		echo -e "\nINFO: Creating CA private key <$CA_PRIVATE_KEY_FILE>"
		generateRootCaPrivateKey "$CA_PRIVATE_KEY_FILE" "$ROOT_KEY_PASSWORD"


		echo -e "\nINFO: Creating CA public key <$CA_PUBLIC_KEY_FILE>"
		generateRootCaPublicKey "$CA_PRIVATE_KEY_FILE" "$CA_PUBLIC_KEY_FILE" "$ROOT_KEY_PASSWORD"
		

		echo -e "\nINFO: Creating CA root cert <$CA_CERT_FILE>"
		generateRootCaCert "$CA_PRIVATE_KEY_FILE" "$CA_CERT_FILE" "$CA_CERT_SUBJECT_LINE" "$ROOT_KEY_PASSWORD"
		
	
		echo -e "\nINFO: Creating CA signing key <$CA_PRIVATE_SIGNING_KEY_FILE>"
		generateRootCaPrivateKey "$CA_PRIVATE_SIGNING_KEY_FILE" "$SIGNING_KEY_PASSWORD"
		
		echo -e "\nINFO: Creating CA public signing key <$CA_PUBLIC_SIGNING_KEY_FILE>"
		generateRootCaPublicKey "$CA_PRIVATE_SIGNING_KEY_FILE" "$CA_PUBLIC_SIGNING_KEY_FILE" "$SIGNING_KEY_PASSWORD"
		
		echo -e "\nINFO: Creating CSR for CA signing key <$CA_PRIVATE_SIGNING_KEY_FILE>"
		echo "INFO: Creating CA sign key cert csr <$CA_SIGNING_KEY_CSR_FILE>"
		generateCsr "$CA_PRIVATE_SIGNING_KEY_FILE" "$CA_SIGNING_KEY_CSR_FILE" "$CA_SINGN_KEY_CERT_SUBJECT_LINE" "$CA_CERT_EXPIRE_DAYS" "$CA_HASH_ALGO" "$SIGNING_KEY_PASSWORD"

		echo -e "\nINFO: Creating CA signing cert <$CA_SIGNING_KEY_CERT_FILE>"
		signCsr "$CA_SERIAL_FILE" "$CA_SIGNING_KEY_CSR_FILE" "$CA_CERT_FILE" "$CA_PRIVATE_KEY_FILE" "$CA_SIGNING_KEY_CERT_FILE" "$CA_CERT_EXPIRE_DAYS" "$CA_HASH_ALGO" "$ROOT_KEY_PASSWORD"

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
	local CN="$7"
	local CA=$8

	local CA_FOLDER=$(getCaFolder "$ROOT_FOLDER" "$CA")
    echo -e "\nINFO: Checking CA Folders in <$CA_FOLDER>"

	checkCaFolders "$CA_FOLDER"

	local CA_SERIAL_FILE=$(getFileName "$ROOT_FOLDER" "$CA" "$CA" "ca" "private" "SERIAL") 
	local HOST_PRIVATE_KEY_FILE=$(getFileName "$ROOT_FOLDER" "$CA" "$CN" "hosts" "private" "PRIVKEY") 
	local HOST_PUBLIC_KEY_FILE=$(getFileName "$ROOT_FOLDER" "$CA" "$CN" "hosts" "public" "PUBKEY") 
	local HOST_KEY_CSR_FILE=$(getFileName "$ROOT_FOLDER" "$CA" "$CN" "hosts" "private" "CSR")
	local CA_SIGNING_KEY_CERT_FILE=$(getFileName "$ROOT_FOLDER" "$CA" "$CA" "ca" "public" "SIGNCERT")
	local CA_PRIVATE_SIGNING_KEY_FILE=$(getFileName "$ROOT_FOLDER" "$CA" "$CA" "ca" "private" "PRIVSIGNKEY")
	local HOST_CERT_FILE=$(getFileName "$ROOT_FOLDER" "$CA" "$CN" "hosts" "public" "CERT")
	local HOST_CERT_SUBJECT_LINE=$(generateCertSubjectLine "$CC" "$ST" "$L" "$O" "$OU" "$CN")


	local SIGNING_KEY_PASSWORD=$(readPasswordInput "CA signing key password")
    local HOST_KEY_PASSWORD=$(readPasswordInput "Host private key password")

	echo -e "\nINFO: Creating Host key <$HOST_PRIVATE_KEY_FILE>"
	generateHostPrivateKey "$HOST_PRIVATE_KEY_FILE" "$HOST_KEY_PASSWORD"


	echo -e "\nINFO: Creating Host public key <$HOST_PUBLIC_KEY_FILE>"
	generateRootCaPublicKey "$HOST_PRIVATE_KEY_FILE" "$HOST_PUBLIC_KEY_FILE" "$HOST_KEY_PASSWORD"

	echo -e "\nINFO: Creating CSR for Host key <$HOST_PRIVATE_KEY_FILE>"
	echo "INFO: Creating Host key cert csr <$HOST_KEY_CSR_FILE>"
	generateCsr "$HOST_PRIVATE_KEY_FILE" "$HOST_KEY_CSR_FILE" "$HOST_CERT_SUBJECT_LINE" "$HOST_CERT_EXPIRE_DAYS" "$HOST_HASH_ALGO"


	echo -e "\nINFO: Sining CSR for Host cert <$HOST_CERT_FILE>"
	signCsr "$CA_SERIAL_FILE" "$HOST_KEY_CSR_FILE" "$CA_SIGNING_KEY_CERT_FILE" "$CA_PRIVATE_SIGNING_KEY_FILE" "$HOST_CERT_FILE" "$HOST_CERT_EXPIRE_DAYS" "$HOST_HASH_ALGO" "$SIGNING_KEY_PASSWORD"

	ROOT_KEY_PASSWORD=""
	SIGNING_KEY_PASSWORD=""
}

##### Tool flow

P_MODE="$1"
P_DATA_FOLDER="$2"
P_CA_FQDN="$3"
P_CC="$4"
P_ST="$5"
P_L="$6"
P_O="$7"
P_OU="$8"
P_SUBJECT="$9"

if ([[ "$P_MODE" = "ca" ]] && [[ "$#" = 8 ]]); then

	createCA "$P_DATA_FOLDER" "$P_CC" "$P_ST" "$P_L" "$P_O.de" "$P_OU" "$P_CA_FQDN" 

elif ([[ "$P_MODE" = "host" ]] && [[ "$#" = 9 ]]); then

	createHost "$P_DATA_FOLDER" "$P_CC" "$P_ST" "$P_L" "$P_O.de" "$P_OU" "$P_SUBJECT" "$P_CA_FQDN"

else

	echo "ERROR: Invalid arguments"
	printCmdInfo
fi 
