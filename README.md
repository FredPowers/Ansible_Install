# Ansible_Install
Script d'installation et configuration d'Ansible sur Debian


.NOTES
NAME:	Ansible_Install.sh
VERSION : 1.0  01/02/2023
AUTHOR:	Frédéric Puren

Script testé sur Debian 11.6

# ------------- préparation des nodes ------------------

# Sur les nodes debian :
	 - créer l'utilisateur ansible et le passer sudo
	 - installer openssh-server



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

#------------------------------------------------------------------------------------------------

Le script commence par une mise à jour des paquets, si le réseau n'est pas disponible ou si il y a une erreur dans le fichier
/etc/apt/sources.list le script indique un message d'erreur et s'arrete.


# 0 choix de l'utilisateur


![2023-02-14 13_22_49-DebSrv - VMware Workstation 16 Player (Non-commercial use only)](https://user-images.githubusercontent.com/105367565/218738082-7e4ab004-bd49-4274-a053-961bba144473.png)


![2023-02-14 13_23_07-DebSrv - VMware Workstation 16 Player (Non-commercial use only)](https://user-images.githubusercontent.com/105367565/218738127-81f2ca22-a3ce-461e-8854-ee043f218d68.png)



# 1 : Installation de Ansible"


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

	#le fichier inventory_Debian_hosts.csv sert d'exemple afin d'importer la liste des hôtes automatiquement dans le fichier d'inventaire Debian


# 3 : Création du fichier d'inventaire pour hôtes windows

	#le fichier inventory_Windows_hosts.csv sert d'exemple afin d'importer la liste des hôtes automatiquement dans le fichier d'inventaire Windows

# 4 : Test ping & Tests Playbooks


![2023-02-14 13_23_27-DebSrv - VMware Workstation 16 Player (Non-commercial use only)](https://user-images.githubusercontent.com/105367565/218739182-08a4164d-7338-44f6-8c29-e93539a7a376.png)

