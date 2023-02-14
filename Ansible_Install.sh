#!/bin/bash


#.NOTES
#	NAME:	Ansible_Install.sh
#   VERSION : 1.0  01/02/2023
#	AUTHOR:	Frédéric Puren

# Script testé sur Debian 11.6

# --------------------------------------- préparation des nodes -------------------------------------------

# Sur les nodes debian :
	# - créer l'utilisateur ansible et le passer sudo
	# - installer openssh-server



# Sur les nodes windows :
	# - Activer WinRM pour la gestion à distance 
		# > Start-Service WinRM

 		# Si WinRm n’est pas installé il faut installer le package Windows Management Framework 4.0 


	# - Configurer WinRM: 

		# > Enable-PSRemoting 

	# - autoriser un hôte a se connecter à distance
		# > Set-Item WSMan:\localhost\Client\TrustedHosts <IP ou nom hote>
 

	# > Restart-Service WinRM 

 	# Vérifier la configuration WinRM : 
		# > winrm get winrm/config/client 

 
	# - Si besoin autoriser les requetes via le pare-feu : 
		# > netsh advfirewall firewall add rule Profile=Domain name="Autoriser WinRM HTTPS" dir=in localport=5986 protocol=TCP action=allow 




# 1 : Installation de Ansible"
# ---------------------------

	# installation des packages suivants via apt :
			# - openssh-server 
			# - openssh-client
			# - python3
			# - python3-pip
			# - python3-dev
			# - libkrb5-dev
			# - krb5-user
			# - gcc
			# - ansible

	# installation des modules suivants via pip :
	# les modules kerberos servent pour l'identification avec un utilisateur du domaine
			# - pywinrm
			# - kerberos
			# - pykerberos
			# - requests-kerberos


	# Génération de la paire de clé ssh



# 2 : Création du fichier d'inventaire pour hôtes debian
# -------------------------------------------------------



# 3 : Création du fichier d'inventaire pour hôtes windows
# -------------------------------------------------------


# 4 : Test ping & Tests Playbooks
# -------------------------------

# ------------------------------------------------------------------------------------------------------------
########### variables des couleurs
orange='\033[33m'
magenta='\033[35m'
vert='\033[32m'
bleu='\033[36m'
bleu_fonce='\033[34m'
rouge='\033[31m'
normal='\033[0m'
#########################################



############### fonctions ##############
host_users (){

echo "utilisateurs présents :"
echo "---------------------"
echo
user=$(getent passwd {1000..2000})
a=1
liste=()
liste2=()

for line in $user
do
	nom=$(echo $line | awk -F":" {'print $1'})

	echo "$a - $nom"
	
	liste=("${liste[@]}" "$nom")
	liste2=("${liste2[@]}" "$a")
	((a=a+1))

done
}
#########################################


################# Debut du script ###################

echo
date=$(date)
echo "############################################################"
echo "#             $date                                        #"
echo "############################################################"
echo
echo


echo -e ""$vert"apt update$normal"
echo -e ""$vert"---------------------------------------$normal"
echo
sleep 2
if apt update -y | grep -E "Erreur|Impossible"
then
	echo 
	echo -e ""$rouge"Les dépots pour l'installation ne sont pas joignables"
	echo -e "La configuration réseau est incorrect ou le fichier /etc/apt/sources.list est erroné$normal"
	echo 
	read -n1 -r -p "Appuyer sur entrée pour arreter"
	exit 0
else
	echo -e ""$orange"--------------------- update terminée ------------------$normal"
fi
echo

if apt list --installed | grep ^bc/stable 1>/dev/null
then
	1>/dev/null
else
	if 	apt install bc -y | grep -E "Erreur|Impossible"
	then
		echo 
		echo -e ""$orange"Les dépots pour l'installation ne sont pas joignables$normal"
		echo -e ""$orange"La configuration réseau est incorrect ou le fichier /etc/apt/sources.list est erroné$normal"
		echo 
		read -n1 -r -p "Appuyer sur entrée pour arreter"
		exit 0
	else
		echo -e ""$orange"--------------------- Installations de bc terminée ------------------$normal"
	fi
fi



if apt list --installed | grep sudo/stable 1>/dev/null
then
	1>/dev/null
else
	apt install sudo -y 1>/dev/null
fi


if apt list --installed | grep sshpass/stable 1>/dev/null
then
	1>/dev/null
else
	apt install sshpass -y 1>/dev/null
fi


if apt list --installed | grep tree/stable 1>/dev/null
then
	1>/dev/null
else
	apt install tree -y 1>/dev/null
fi

echo


version=$(cat /etc/debian_version)

echo -e "verion de debian installée : $vert$version$normal"
echo
if (( $(echo "$version < 11" | bc -l) ))
then
	echo -e ""$orange"la version de debian qui exécute ce script est antérieur à celle où celui-ci a été testé"
	echo -e "Voulez-vous continuer ? [O/N]$normal"
	read -p "" -r reponse

	while [[ $reponse != "O" && $reponse != "o" && $reponse != "N" && $reponse != "n" ]]
	do
		echo
		echo "erreur de frappe, veuille recommencer"
		echo
		echo -e ""$orange"la version de debian qui exécute ce script est antérieur à celle où celui-ci a été testé"
		echo -e "Voulez-vous continuer ? [O/N]$normal"
		read -p "" -r reponse
	done
	if [[ $reponse == "N" || "$reponse" = "n" ]]
	then
		exit 0
	fi
fi

sleep 2
clear

# lister les utilisateurs

echo -e ""$vert"---------------------------------------"
echo -e "| choix de l'utilisateur pour ansible |"
echo -e "---------------------------------------$normal"
echo
host_users
echo "------------------------"
echo -e ""$bleu"C - Créer un nouvel utilisateur$normal"
echo -e ""$rouge"Q - quitter$normal"
echo
echo -e ""$orange"entrer le chiffre correpondant à l'utilisateur désiré ou taper 'C' pour créer un nouvel utilisateur$normal"
read -p "@@ -> " choix
echo
echo

while [[ ! "${liste2[*]}" =~ $choix && $choix != "C" && $choix != "c" && $choix != "Q" && $choix != "q" ]]
do
	clear
	echo "erreur de frappe"
	echo
	echo -e ""$vert"choix de l'utilisateur pour ansible$normal"
	echo
	host_users
	echo "------------------------"
	echo -e "C - Créer un nouvel utilisateur local"
	echo "Q - quitter"
	echo
	echo -e ""$orange"entrer le chiffre correpondant à l'utilisateur choisi ou taper 'C' pour créer un nouvel utilisateur :$normal"
	read -p "@@ -> " choix

	
done

if [[ ${liste2[*]} =~ $choix ]]
then
		((indice=$choix-1))

		login=${liste[$indice]}

		echo
		echo -e "choix de l'utilisateur : $vert$login$normal"
		echo

		# vérifier si l'utilisateur est dan le groupe sudo
		if id $login | grep -v sudo
		then
			usermod -aG sudo $login && echo "L'utilisateur $login a été intégré au groupe sudo"
			echo
		fi

elif [[ "$choix" == "C" || "$choix" == "c" ]]
then
		echo -e ""$orange"entrer le nom du compte à créer qui sera dédié à Ansible$normal"
		read -p "@@ -> " login
		echo

		useradd $login --create-home -s /bin/bash && echo ""$vert"Utilisateur $login créé$normal"
		echo
		sleep 2
		usermod -aG sudo $login && echo ""$vert"L'tilisateur $login a été intégré au groupe sudo$normal"
		sleep 2
		passwd $login
		echo

elif [[ "$choix" == "Q" || $choix == "q" ]]
then
	exit
fi

script () {

while :
do
	echo
	echo -e ""$vert"########################################################"
	echo -e "#                         MENU                         #"
	echo -e "########################################################$normal"
	echo -e
	echo -e ""$bleu"1 : Installation de Ansible"
	echo -e "2 : Création du fichier d'inventaire pour hôtes debian"
	echo -e "3 : Création du fichier d'inventaire pour hôtes windows"
	echo -e "4 : Test ping & Tests Playbooks$normal"
	echo -e ""$rouge"Q : quitter$normal"
	echo


	read -p "@@ -> " optionmenu
	case $optionmenu in


	1)
		clear

		echo -e "$bleu-----------------------------------$normal"
		echo -e "$bleu      Installation de Ansible      $normal"
		echo -e "$bleu-----------------------------------$normal"
		echo
		echo

		if (apt list --installed | grep openssh-client/stable 1>/dev/null)
		then
				echo
				echo "openssh-client est déjà installé"

		else
				echo "installation avec apt install openssh-client"
				apt install -y openssh-client
				echo 
				echo -e ""$orange"--------------------- Installation d'openssh-client terminée ------------------$normal"	 
		fi
			

		if (apt list --installed | grep openssh-server/stable 1>/dev/null)
		then
				echo
				echo "openssh-server est déjà installé"

		else
				echo "installation avec apt install openssh-server"
				apt install -y openssh-server
				echo 
				echo -e ""$orange"--------------------- Installation openssh-server terminée ------------------$normal"
				sleep 3
		fi


		if (apt list --installed | grep python3/stable 1>/dev/null)
		then
				echo
				echo "python3 est déjà installé"

		else
				echo "installation avec apt install python3"
				apt install python3 -y
				echo 
				echo -e ""$orange"--------------------- Installation de python3 terminée ------------------$normal"
				sleep 3
		fi


		if (apt list --installed | grep python3-pip/stable 1>/dev/null)
		then
				echo
				echo "python3-pip est déjà installé"

		else
				echo "installation avec apt install python3-pip"
				apt install python3-pip -y
				echo 
				echo -e ""$orange"--------------------- Installation de python3-pip terminée ------------------$normal"
				sleep 3
		fi


		if (apt list --installed | grep python-dev/stable 1>/dev/null)
		then
				echo
				echo "python-dev est déjà installé"

		else
				echo "installation avec apt install python-dev"
				apt install python-dev -y
				echo 
				echo -e ""$orange"--------------------- Installation de python-dev terminée ------------------$normal"
				sleep 3
		fi


		if (apt list --installed | grep libkrb5-dev/stable 1>/dev/null)
		then
				echo
				echo "libkrb5-dev est déjà installé"

		else
				echo "installation avec apt install libkrb5-dev"
				apt install libkrb5-dev -y
				echo 
				echo -e ""$orange"--------------------- Installation de libkrb5-dev terminée ------------------$normal"
				sleep 3
		fi

		if (apt list --installed | grep krb5-user/stable 1>/dev/null)
		then
				echo
				echo "krb5-user est déjà installé"

		else
				echo "installation avec apt install krb5-user"
				#export DEBIAN_FRONTEND=noninteractive
				# a tester :
				DEBIAN_FRONTEND=noninteractive apt install krb5-user -y


				echo 
				echo -e ""$orange"--------------------- Installation de krb5-user terminée ------------------$normal"
				sleep 3
		fi


		if (apt list --installed | grep gcc/stable 1>/dev/null)
		then
				echo
				echo "gcc est déjà installé"

		else
				echo "installation avec apt install gcc"
				apt install gcc -y
				echo 
				echo -e ""$orange"--------------------- Installation de gcc terminée ------------------$normal"
				sleep 3
		fi


		if (apt list --installed | grep ansible/stable 1>/dev/null)
		then
				echo
				echo "ansible est déjà installé"

		else
				echo "installation avec apt install ansible"
				apt install ansible -y
				echo 
				echo -e ""$orange"--------------------- Installation de ansible terminée ------------------$normal"
				sleep 3
		fi


		echo
		echo -e ""$vert"Installation de kerberos, pykerberos, requests-kerberos & pywinrm$normal"
		echo -e ""$vert"-----------------------------------------------------------------$normal"
		echo
		pip install kerberos pykerberos requests_kerberos pywinrm
		echo
		echo


		echo -e ""$vert"Vérification des packages installés$normal"
		echo -e ""$vert"-----------------------------------$normal"
		echo
		liste0=""

		liste_apt=( "openssh-server" "openssh-client" "python3" "python3-pip" "python3-dev" "libkrb5-dev" "krb5-user" "gcc" "ansible" )

		echo
		for item1 in ${liste_apt[@]}
		do
			if apt list --installed | grep ^$item1/stable 1>/dev/null
			then
					echo -e ""$vert"$item1 est installé$normal"
			else
					echo -e ""$rouge"$item1 n'est pas installé$normal"
					liste0+=(${liste0[@]} "$item1")
			fi
		done


		liste_pip=( "kerberos" "pykerberos" "requests-kerberos" "pywinrm" )

		for item2 in ${liste_pip[@]}
		do
			if pip list | grep ^$item2 1>/dev/null
			then
					echo -e ""$vert"$item2 est installé$normal"
			else
					echo -e ""$rouge"$item2 n'est pas installé$normal"
					liste0+=("$item2")
			fi
		done

		if [ -z "$liste0" ]
		then
				echo
				echo -e ""$orange"tous les packages requis ont été installé avec succès$normal"
				echo
			
		else
				echo
				echo "Le script va s'arreter"
				read -n1 -r -p "Appuyer sur 'entrée' pour continuer"
				exit 0
		fi

		sleep 3

		echo -e ""$vert"-------------------------------------"
		echo -e ""$vert"| Génération de la paire de clé ssh |"
		echo -e ""$vert"-------------------------------------$normal"
		echo

		# Génération des paires de clé ssh
		mkdir /home/$login/.ssh
		sleep 1
		chown -R "$login":"$login" /home/$login/.ssh

		yes "y" | ssh-keygen -t ed25519 -C "SSH key 4 ansible" -f /home/$login/.ssh/id_rsa -N ""

		sleep 3
		echo
		echo -e ""$vert"-------------------------------------------"
		echo -e ""$vert"| Envoi de la clé publique vers les hôtes |"
		echo -e ""$vert"-------------------------------------------$normal"
		echo
		echo
		echo -e ""$orange"entrer le mot de passe pour $login :$normal"
		read -p "@@ => " -s pass
		echo
		echo

		optionmenu=""

		until [[ $optionmenu == 1 || $optionmenu == 2 ]]
		do

			echo "1 - Rentrer les hôtes manuellement"
			echo "2 - Importer la liste des hôtes à partir d'un fichier"
			echo

			read -p "@@ => " optionmenu
			case $optionmenu in


			1)
				echo
				echo -e ""$orange"entrer l'ip de l'hôte vers qui se connecter en ssh"
				echo -e "séparer d'un espace si plusieurs hôtes sont déclarés$normal"

				read -p "@@ => " host

				for item in $host
				do
						sshpass -p $pass ssh-copy-id "$login"@"$item"
				done
				echo
				;;

			2)
				script_rep=$(dirname $(readlink -f $0))
				echo
				echo -e ""$orange"rentrer le chemin complet du fichier csv, ex : /home/$login/fichier.csv"
				echo -e "Si vous laisser vide, le fichier d'exemple /chemin du script/inventory_Debian_hosts.csv sera choisi$normal"

				read -p "@@ => " chemin
				echo

				if [ -z $chemin ]
				then
					while IFS="," read -r nom ip
					do
						sshpass -p $pass ssh-copy-id "$login"@"$nom"

					done < $script_rep/inventory_Debian_hosts.csv
				else
					while IFS="," read -r nom ip
					do
						sshpass -p $pass ssh-copy-id "$login"@"$nom"

					done < $chemin
				fi
				;;

			
			*)
				echo "erreur de frappe"
				read -n1 -r -p "Appuyer sur entrée pour recommencer"
				clear
				;;
			esac
		done


		echo -e ""$orange"############################################################$normal"
		echo -e ""$orange"#                   Configuration d'Ansible                #$normal"
		echo -e ""$orange"############################################################$normal"
		echo

		if [ ! -f /home/$login/ansible ]
		then
				mkdir -p /home/$login/ansible/{playbook,group_vars,roles}
		fi

		chown -R $login:$login /home/$login/ansible

		# Création du fichier de configuration d'Ansible
		echo "[defaults]

inventory=/home/$login/ansible/inventory
remote_user=$login
host_key_checking=False
become=True
become_user=$login
become_ask_pass=False" > /home/$login/ansible/ansible.cfg
					
		chown -R $login:$login /home/$login/ansible/ansible.cfg
		
		touch /home/$login/ansible/Deb-inventory

		chown -R $login:$login /home/$login/ansible/Deb-inventory
		sleep 1

		# Export vers /home/$login/.profile de la nouvelle configuration d'ansible
		export ANSIBLE_CONFIG=/home/$login/ansible/ansible.cfg

		if grep -v "ANSIBLE_CONFIG" /home/$login/.profile
		then
				echo "export ANSIBLE_CONFIG=/home/$login/ansible/ansible.cfg" >> /home/$login/.profile
				sleep 1
				. /home/$login/.profile
		fi

		#Vérification de la configuration
		verif=$(ansible --version)

		cd /home/$login/ansible/

		if echo "$verif" | grep "config file = /home/$login/ansible/ansible.cfg"
		then
				echo
				echo -e ""$vert"fichier de configuration ansible OK$normal"
				echo
		else
				echo "fichier de configuration KO"
				echo "la ligne 'config file' est erronée"
				echo 
				echo "$verif"
		fi

		echo
		echo -e ""$orange"Vos hôtes font-ils partie d'un domaine sous Windows serveur ? [O/N]$normal"
		read -p "@@ => " reponse
		echo

		while [[ $reponse != "O" && $reponse != "o" && $reponse != "N" && $reponse != "n" ]]
		do
			echo
			echo "erreur de frappe, veuille recommencer"
			echo
			echo -e ""$orange"Vos hôtes font-ils partie d'un domaine sous Windows serveur ? [O/N]$normal"
			read -p "@@ => " reponse
			echo
		done

		if [[ "$reponse" == "O" ]]
		then
			echo -e ""$orange"Merci d'entrer le nom du domaine en majuscule, ex TEST.LOCAL$normal"
			read -p "@@ => " domaine
			echo
			sed -i 's/\\tdefault_realm = ATHENA.MIT.EDU;/default_realm = '$domaine';/g' /etc/krb5.conf

			sed -i '2d' /etc/krb5.conf
			sed -i '2i\\tdefault_realm = '$domaine'' /etc/krb5.conf

			sed -i 's/#KerberosAuthentication no/KerberosAuthentication yes/g' /etc/ssh/sshd_config
			sed -i 's/#KerberosOrLocalPasswd yes/KerberosOrLocalPasswd yes/g' /etc/ssh/sshd_config
			sed -i 's/#KerberosTicketCleanup yes/KerberosTicketCleanup yes/g' /etc/ssh/sshd_config

			sed -i 's/#GSSAPIAuthentication no/GSSAPIAuthentication yes/g' /etc/ssh/sshd_config
			sed -i 's/#GSSAPIKeyExchange no/GSSAPIKeyExchange yes/g' /etc/ssh/sshd_config
			sed -i 's/#GSSAPICleanupCredentials yes/GSSAPICleanupCredentials yes/g' /etc/ssh/sshd_config
		fi

		sleep 3

		tree /home/$login/ansible
		echo
		echo
		echo "################## Fin de l'installation d'Ansible ###################"
		echo
		read -n1 -r -p "Appuyer sur entrée pour continuer"
		;;

	2)
		clear

		echo -e ""$vert"#################################################################$normal"
		echo -e ""$vert"#       Création du fichier d'inventaire pour hôtes debian      #$normal"
		echo -e ""$vert"#################################################################$normal"
		echo
		echo
		

		while :
		do

			echo -e ""$bleu"1 - Rentrer les hôtes manuellement"
			echo -e "2 - Importer la liste des hôtes à partir d'un fichier$normal"
			echo -e ""$rouge"Q - Revenir au menu principal$normal"
			echo
			read -p "@@ => " optionmenu
			case $optionmenu in


			1)
				echo -e ""$orange"entrez le nom du groupe :$normal"
				read -p "@@ => " -r groupe
				echo
				echo
				echo -e ""$orange"entrez le nom (FQDN si domaine) des hôtes à intégrer au groupe $groupe"
				echo -e "séparez les d'un espace$normal"
				read -p "@@ => " -r nom_host

				echo -e "[$groupe]" >> /home/$login/ansible/Deb-inventory

				for item in ${nom_host[@]}
				do
					echo -e "$item" >> /home/$login/ansible/Deb-inventory

				done

				echo "" >> /home/$login/ansible/Deb-inventory
				echo
				echo "--------------------------------"
				cat /home/$login/ansible/Deb-inventory
				echo "--------------------------------"
				echo
				;;


			2)
				script_rep=$( dirname -- "$0")
				echo
				echo -e ""$orange"entrez le nom du groupe :$normal"
				read -p "@@ => " -r groupe
				echo
				echo -e ""$orange"rentrer le chemin complet du fichier csv, ex : /home/$login/fichier.csv"
				echo -e "Si vous laisser vide, le fichier d'exemple /chemin du script/inventory_Debian_hosts.csv sera choisi$normal"
				echo
				read -p "@@ => " chemin
				echo

				echo -e "[$groupe]" >> /home/$login/ansible/Deb-inventory

				if [ -z $chemin ]
				then
					while IFS="," read -r nom ip
					do
						echo "$nom" >> /home/$login/ansible/Deb-inventory

					done < $script_rep/inventory_Debian_hosts.csv
				else
					while IFS="," read -r nom ip
					do
						echo "$nom" >> /home/$login/ansible/Deb-inventory

					done < $chemin
				fi
				echo "" >> /home/$login/ansible/Deb-inventory
				echo
				echo "--------------------------------"
				cat /home/$login/ansible/Deb-inventory
				echo "--------------------------------"
				echo
				;;

			[Qq])
				clear
				script
				;;

			*)
				echo "erreur de frappe"
				read -n1 -r -p "Appuyer sur entrée pour recommencer"
				clear
				;;
			esac
		done
		;;


	3)
		clear

		echo -e ""$vert"#################################################################$normal"
		echo -e ""$vert"#       Création du fichier d'inventaire pour hôtes windows      #$normal"
		echo -e ""$vert"#################################################################$normal"
		echo

		while :
		do

			echo -e ""$bleu"1 - Rentrer les hôtes manuellement"
			echo -e "2 - Importer la liste des hôtes à partir d'un fichier$normal"
			echo -e ""$rouge"Q - Revenir au menu principal$normal"


			read -p "@@ => " optionmenu
			case $optionmenu in


			1)
				echo -e ""$orange"entrez le nom du groupe :$normal"
				read -p "@@ => " -r groupe
				echo
				echo
				echo -e ""$orange"entrez le nom (FQDN si domaine) des hôtes à intégrer au groupe $groupe"
				echo -e "séparez les d'un espace$normal"
				read -p "@@ => " -r nom_host

				echo -e "[$groupe]" >> /home/$login/ansible/Win-inventory

				for item in ${nom_host[@]}
				do
					echo -e "$item" >> /home/$login/ansible/Win-inventory

				done

				echo "" >> /home/$login/ansible/Win-inventory
				echo
				echo "Création du fichier .yml associé au groupe"
				echo
				echo -e "Emplacement du fichier qui sera créé : "$vert"/home/$login/ansible/group_vars/$groupe.yml$normal"
				echo 
				sleep 1

				if [ ! -f /home/$login/ansible/group_vars/$groupe.yml ]
				then
					echo -e ""$orange"entrez le login du compte windows qui servira pour la connexion aux hôtes distants"
					echo -e "sous la forme user@domaine.tld$normal"
					read -p "@@ => " -r compte
				
					echo "ansible_user: $compte
ansible_pass:
ansible_port: 5986
ansible_connection: winrm
ansible_winrm_server_cert_validation: ignore" >> /home/$login/ansible/group_vars/$groupe.yml

				chown -R $login:$login /home/$login/ansible/group_vars/$groupe.yml
				fi

				echo "--------------------------------"
				cat /home/$login/ansible/Win-inventory
				echo "--------------------------------"
				echo
				;;


			2)
				script_rep=$( dirname -- "$0")
				echo
				echo -e ""$orange"entrez le nom du groupe :$normal"
				read -p "@@ => " -r groupe
				echo
				echo -e ""$orange"rentrer le chemin complet du fichier csv, ex : /home/$login/fichier.csv"
				echo -e "Si vous laisser vide, le fichier d'exemple /chemin du script/inventory_Windows_hosts.csv sera choisi$normal"
				echo
				read -p "@@ => " chemin
				echo

				echo -e "[$groupe]" >> /home/$login/ansible/Win-inventory

				# récupérer le nom de domaine inscrit dans le fichier krb5.conf
				# si ATHENA.MIT.EDU pas de domaine configuré
					   #2ème ligne du fichier	    #séparateur '=' 2ème mot  #supprimer l'espace en début de mot
				test=$(sed -n "2 p" /etc/krb5.conf | awk -F"=" '{print $2}' | sed "s/^\ *//g")


				if [ -z $chemin ]
				then
					while IFS="," read -r nom ip
					do
						if [ "$test" == "ATHENA.MIT.EDU" ]
						then
							echo "$nom" >> /home/$login/ansible/Win-inventory
						else
							echo "$nom.$test" >> /home/$login/ansible/Win-inventory
						fi
					done < $script_rep/inventory_Windows_hosts.csv
				else
					while IFS="," read -r nom ip
					do
						if [ "$test" == "ATHENA.MIT.EDU" ]
						then
							echo "$nom" >> /home/$login/ansible/Win-inventory
						else
							echo "$nom.$test" >> /home/$login/ansible/Win-inventory
						fi
					done < $chemin
				fi
				echo "" >> /home/$login/ansible/Win-inventory
				echo

				echo "Création du fichier .yml associé au groupe"
				echo
				echo -e "Emplacement du fichier qui sera créé : "$vert"/home/$login/ansible/group_vars/$groupe.yml$normal"
				echo 
				sleep 1

				if [ ! -f /home/$login/ansible/group_vars/$groupe.yml ]
				then
					echo -e ""$orange"entrez le login du compte windows qui servira pour la connexion aux hôtes distants"
					echo -e "Le login sera sous la forme login@DOMAINE.TLD si c'est un compte de domaine"$normal
					echo
					read -p "@@ => " -r compte
				
					echo "ansible_user: $compte
ansible_pass:
ansible_port: 5986
ansible_connection: winrm
ansible_winrm_server_cert_validation: ignore" >> /home/$login/ansible/group_vars/$groupe.yml

				chown -R $login:$login /home/$login/ansible/group_vars/$groupe.yml
				fi

				echo "--------------------------------"
				cat /home/$login/ansible/Win-inventory
				echo "--------------------------------"
				echo
				;;


			[Qq])
				clear
				script
				;;

			*)
				echo "erreur de frappe"
				read -n1 -r -p "Appuyer sur entrée pour recommencer"
				clear
				;;
			esac
		done

		echo
		tree /home/$login/ansible
		echo
		read -n1 -r -p "Appuyer sur entrée pour continuer"
		clear
		;;

		4)
			clear

			while :
			do
				echo -e ""$vert"################################################"
				echo -e "#                    Tests                     #"
				echo -e "################################################$normal"
				echo
				echo -e ""$bleu"1 : Ping avec module ping (hôtes Linux)"
				echo -e "2 : Ping avec module win_ping (hôtes Windows)"
				echo -e "3 : Test Playbook Windows - Install_VLC"
				echo -e "4 : Test Playbook Windows - Uninstall_VLC"
				echo -e "5 : Test Playbook Debian - Install_Neofetch"
				echo -e "6 : Test Playbook Debian - Uninstall_Neofetch"
				echo -e "7 : Afficher l'arborescence du dossier ansible$normal"
				echo -e ""$rouge"q : quitter$normal"
				echo
				echo "@@ => "


				read optionmenu
				case $optionmenu in


				1)
					clear
					echo -e ""$vert"-------------------------------------------"
					echo -e ""$vert"| 1 : Ping avec module ping (hôtes Linux) |"
					echo -e ""$vert"-------------------------------------------$normal"
					echo
					echo -e ""$orange"entrez le nom d'un groupe ou d'un hôte présent dans le fichier d'inventaire 'inventory' :$normal"
					echo
					echo "----------------------------"
					cat /home/$login/ansible/Deb-inventory
					echo "----------------------------"
					echo
					read -p "@@ => " -r groupe1
					echo
					ansible -u $login -i /home/$login/ansible/Deb-inventory -m ping $groupe1
					echo
					read -n1 -r -p "Appuyer sur entrée pour continuer"
					clear
					;;

				2)
					clear
					echo -e ""$vert"-------------------------------------------------"
					echo -e ""$vert"| 2 : Ping avec module win_ping (hôtes Windows) |"
					echo -e ""$vert"-------------------------------------------------$normal"
					echo
					echo -e ""$orange"entrez le nom d'un groupe ou d'un hôte présent dans le fichier d'inventaire 'Win-inventory' :$normal"
					echo
					echo "-----------------------------"
					cat /home/$login/ansible/Win-inventory
					echo "-----------------------------"
					echo
					read -p "@@ => " -r groupe2
					echo 
					ansible -i /home/$login/ansible/Win-inventory -m win_ping $groupe2 --ask-pass
					echo
					read -n1 -r -p "Appuyer sur entrée pour continuer"
					clear
					;;

				3)
					clear
					echo -e ""$vert"-------------------------------------------"
					echo -e ""$vert"| 3 : Test Playbook Windows - Install_VLC |"
					echo -e ""$vert"-------------------------------------------$normal"
					echo
					echo -e ""$orange"entrez le nom d'un groupe ou d'un hôte présent dans le fichier d'inventaire 'Win-inventory' :$normal"
					echo
					echo "-----------------------------"
					cat /home/$login/ansible/Win-inventory
					echo "-----------------------------"
					echo
					read -p "@@ => " -r groupe3
					echo 


					if [ ! -f /home/$login/ansible/playbook/Install_VLC.yml ]
					then

							echo "---
- name: Installing VLC msi 
  hosts: $groupe3

  tasks:
    - name: Create ansible directory in C
      ansible.windows.win_file:
        path: C:\ansible
        state: directory

    - name: Download the VLC installer
      win_get_url:
        url: https://get.videolan.org/vlc/3.0.18/win64/vlc-3.0.18-win64.msi
        dest: C:\ansible\vlc-3.0.18-win64.msi

    - name: Install VLC
      win_package:
        path: C:\ansible\vlc-3.0.18-win64.msi
        state: present" > /home/$login/ansible/playbook/Install_VLC.yml


        				chown -R $login:$login /home/$login/ansible/playbook/Install_VLC.yml
        			fi

        			ansible-playbook -u $login -i /home/$login/ansible/Win-inventory /home/$login/ansible/playbook/Install_VLC.yml  --ask-pass
        			echo
        			read -n1 -r -p "Appuyer sur entrée pour continuer"
					clear
					;;


				4)
					clear
					echo -e ""$vert"---------------------------------------------"
					echo -e ""$vert"| 4 : Test Playbook Windows - Uninstall_VLC |"
					echo -e ""$vert"---------------------------------------------$normal"
					echo
					echo -e ""$orange"entrez le nom d'un groupe ou d'un hôte présent dans le fichier d'inventaire 'Win-inventory' :$normal"
					echo
					echo "-----------------------------"
					cat /home/$login/ansible/Win-inventory
					echo "-----------------------------"
					echo
					read -p "@@ => " -r groupe4
					echo 

					if [ ! -f /home/$login/ansible/playbook/Uninstall_VLC.yml ]
					then

						echo "---
- name: UnInstalling VLC

  hosts: $groupe4

  tasks:
    - name: UnInstall VLC
      win_package: 
        path: C:\ansible\vlc-3.0.18-win64.msi
        state: absent

    - name: Delete ansible directory in C
      ansible.windows.win_file:
        path: C:\ansible
        state: absent" > /home/$login/ansible/playbook/Uninstall_VLC.yml


        				chown -R $login:$login /home/$login/ansible/playbook/Uninstall_VLC.yml
        			fi

        			ansible-playbook -u $login -i /home/$login/ansible/Win-inventory /home/$login/ansible/playbook/Uninstall_VLC.yml  --ask-pass
        			echo
        			read -n1 -r -p "Appuyer sur entrée pour continuer"
					clear
        			;;

        		5)
					clear
					echo -e ""$vert"-----------------------------------------------"
					echo -e ""$vert"| 5 : Test Playbook Debian - Install_Neofetch |"
					echo -e ""$vert"-----------------------------------------------$normal"
					echo
					echo -e ""$orange"entrez le nom d'un groupe ou d'un hôte présent dans le fichier d'inventaire 'inventory' :$normal"
					echo
					echo "----------------------------"
					cat /home/$login/ansible/Deb-inventory
					echo "----------------------------"
					echo
					read -p "@@ => " -r groupe5
					echo 

					if [ ! -f /home/$login/ansible/playbook/Install_Neofetch.yml ]
					then

					echo "---
- name: Installing Neofetch
  hosts: $groupe5
  become: yes
  
  tasks:
    - name: Install Neofetch
      
      apt:
        
        name: neofetch
        state: latest" > /home/$login/ansible/playbook/Install_Neofetch.yml


        				chown -R $login:$login /home/$login/ansible/playbook/Install_Neofetch.yml
        			fi

        			ansible-playbook -u $login -i /home/$login/ansible/inventory /home/$login/ansible/playbook/Install_Neofetch.yml -K
        			echo
        			read -n1 -r -p "Appuyer sur entrée pour continuer"
					clear
					;;


					6)
						clear
						echo -e ""$vert"-------------------------------------------------"
						echo -e ""$vert"| 6 : Test Playbook Debian - Uninstall_Neofetch |"
						echo -e ""$vert"-------------------------------------------------$normal"
						echo
						echo -e ""$orange"entrez le nom d'un groupe ou d'un hôte présent dans le fichier d'inventaire 'inventory' :$normal"
						echo
						echo "----------------------------"
						cat /home/$login/ansible/Deb-inventory
						echo "----------------------------"
						echo
						read -p "@@ => " -r groupe6
						echo 

						if [ ! -f /home/$login/ansible/playbook/Uninstall_Neofetch.yml ]
						then

							echo "---
- name: Uninstalling Neofetch
  hosts: $groupe6
  become: yes

  tasks:
    - name: Uninstall Neofetch

      apt:
        name: neofetch 
        state: absent
        purge: yes
        autoremove: yes" > /home/$login/ansible/playbook/Uninstall_Neofetch.yml


        					chown -R $login:$login /home/$login/ansible/playbook/Uninstall_Neofetch.yml
        				fi

        				ansible-playbook -u $login -i /home/$login/ansible/inventory /home/$login/ansible/playbook/Uninstall_Neofetch.yml --ask-become-pass
        				echo
        				read -n1 -r -p "Appuyer sur entrée pour continuer"
						clear
						;;

					7)
						clear
						echo -e ""$vert"---------------------------------------------------"
						echo -e ""$vert"| 7 : Afficher l'arborescence du dossier ansible$ |"
						echo -e ""$vert"---------------------------------------------------$normal"
						echo
						tree /home/$login/ansible
						echo
						read -n1 -r -p "Appuyer sur entrée pour continuer"
						clear
						;;

				[qQ])
						clear
						script
						;;


					*)
						echo "erreur de frappe"
						read -n1 -r -p "Appuyer sur entrée pour recommencer"
						clear
						;;
				esac
			done
			;;


	[qQ])
			clear
			exit
			;;


		*)
			echo "erreur de frappe"
			read -n1 -r -p "Appuyer sur entrée pour recommencer"
			clear
			;;
	esac
done
}

script |& tee -a /root/Ansible_Install.log
