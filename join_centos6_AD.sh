#!/bin/bash

upcase () 
{
	echo -n $(echo $1 | tr '[a-z]' '[A-Z]')
}
workgroup () 
{
	echo -n $(upcase $(dnsdomainname | cut -d. -f1))
}

realm () 
{
	echo -n $(upcase $(dnsdomainname))
}

netbios_name () 
{
	echo -n $(hostname -s)
}

configure_samba () 
{
	cp /etc/samba/smb.conf{,.adjoinsave}

	cat <<-EOF > /etc/samba/smb.conf
	[global]

	   workgroup = $(workgroup)
	   netbios name = $(netbios_name)
	   realm = $(realm)
	   security = ads
	   idmap config * : range = 1000-1000000
	   idmap config * : backend = tdb
	   idmap config $(workgroup) : default = yes
	   idmap config $(workgroup) : schema_mode = rfc2307
	   idmap config $(workgroup) : range = 1000-1000000
	   idmap config $(workgroup) : backend = rid
	   password server = $(lookup_kdc)
	   template homedir = /home/$(workgroup)/%U
	   template shell = /bin/bash
	   winbind nss info = rfc2307
	   winbind separator = +
	   winbind use default domain = Yes
	   winbind offline logon = Yes
	   winbind enum users = Yes
	   winbind enum groups = Yes
	   server string = Samba Server Version %v
	   # log files split per-machine:
	   log file = /var/log/samba/log.%m
	   # maximum size of 50KB per log file, then rotate:
	   max log size = 50
	   passdb backend = tdbsam
	   load printers = yes
	   cups options = raw
	   # obtain a list of printers automatically on UNIX System V systems:

	[homes]
	   comment = Home Directories
	   browseable = no
	   writable = yes

	[printers]
	   comment = All Printers
	   path = /var/spool/samba
	   browseable = no
	   guest ok = no
	   writable = no
	   printable = yes
	EOF
}

configure_nsswitch () 
{
	cp /etc/nsswitch.conf{,.adjoinsave}

	cat <<-EOF > /etc/nsswitch.conf
	#
	# /etc/nsswitch.conf
	#
	# An example Name Service Switch config file. This file should be
	# sorted with the most-used services at the beginning.
	#
	# The entry '[NOTFOUND=return]' means that the search for an
	# entry should stop if the search in the previous entry turned
	# up nothing. Note that if the search failed due to some other reason
	# (like no NIS server responding) then the search continues with the
	# next entry.
	#
	# Valid entries include:
	#
	#	nisplus			Use NIS+ (NIS version 3)
	#	nis			Use NIS (NIS version 2), also called YP
	#	dns			Use DNS (Domain Name Service)
	#	files			Use the local files
	#	db			Use the local database (.db) files
	#	compat			Use NIS on compat mode
	#	hesiod			Use Hesiod for user lookups
	#	[NOTFOUND=return]	Stop searching if not found so far
	#
	
	# To use db, put the "db" in front of "files" for entries you want to be
	# looked up first in the databases
	#
	# Example:
	#passwd:    db files nisplus nis
	#shadow:    db files nisplus nis
	#group:     db files nisplus nis
	
	passwd:     files winbind
	shadow:     files winbind
	group:      files winbind
	
	#hosts:     db files nisplus nis dns
	hosts:      files wins dns
	
	# Example - obey only what nisplus tells us...
	#services:   nisplus [NOTFOUND=return] files
	#networks:   nisplus [NOTFOUND=return] files
	#protocols:  nisplus [NOTFOUND=return] files
	#rpc:        nisplus [NOTFOUND=return] files
	#ethers:     nisplus [NOTFOUND=return] files
	#netmasks:   nisplus [NOTFOUND=return] files
	
	bootparams: nisplus [NOTFOUND=return] files
	
	ethers:     files
	netmasks:   files
	networks:   files
	protocols:  files
	rpc:        files
	services:   files
	
	netgroup:   files
	
	publickey:  nisplus
	
	automount:  files
	aliases:    files nisplus
		
	EOF
}


lookup_kdc ()
{
	local res=$(host -t srv _kerberos._tcp.$(dnsdomainname) | head -1 | awk '{print $8}') 
	echo ${res%?}
}
configure_ntp () 
{
	echo "Updating Time"
	echo "-------------"
	ntpdate $1
	echo
	echo "STRONGLY consider adding the following to"
	echo "/etc/ntp.conf"
	for x in $(host -t srv _kerberos._tcp.$(dnsdomainname)| awk '{print $8}');
	do
		echo "server ${x%?}"
	done
}

configure_kerberos () 
{
	cp /etc/krb5.conf{,.adjoinsave}
	kdc=$(lookup_kdc)
	

	echo "KERBEROS:"
	echo "It looks like ${kdc} is answering requests." 
	echo 
	local kdc_answer
	read -p "Do you want to use ${kdc} to serve Kerberos logins? [Y/n]: " kdc_answer
	
	case $kdc_answer in
		[yY])
			admin_server=$kdc
			kdc_server=$kdc
			;;
	  	*)
			read -p "kdc? [${kdc}]: " kdc
			read -p "admin server [${kdc}]: " admin_server
			read -p "kdc_server [${kdc}]: " kdc_server
			;;
	esac 

	configure_ntp $kdc
	

	cat <<-EOF > /etc/krb5.conf
	[logging]
	default = FILE:/var/krb5/kdc.log
	kdc = FILE:/var/krb5/kdc.log
	admin_server = FILE:/var/log/kadmind.log
	
	[libdefaults]
	default_realm = $(realm)
	dns_lookup_realm = false
	dns_lookup_kdc = false
	rdns = false
	ticket_lifetime = 24h
	renew_lifetime = 7d
	forwardable = true
	default_tkt_enctypes = aes256-cts-hmac-sha1-96 rc4-hmac des-cbc-crc des-cbc-md5
	default_tgs_enctypes = aes256-cts-hmac-sha1-96 rc4-hmac des-cbc-crc des-cbc-md5
	permitted_enctypes =  aes256-cts-hmac-sha1-96 rc4-hmac des-cbc-crc des-cbc-md5
	
	[realms]
	$(realm) = {
	kdc = ${kdc}:88
	admin_server = ${admin_server}
	kdc_server = ${kdc_server}
	 }
	
	[domain_realm]
	$(dnsdomainname) = $(realm)
	.$(dnsdomainname) = $(realm)
	
	EOF
}

configure_pam () 
{
	cp /etc/pam.d/system-auth-ac{,.adjoinsave}
	
	cat <<-EOF > /etc/pam.d/system-auth-ac
	auth        required      pam_env.so
	auth        sufficient    pam_unix.so nullok try_first_pass
	auth        requisite     pam_succeed_if.so uid >= 500 quiet
	auth        sufficient    pam_krb5.so use_first_pass
	auth        sufficient    pam_winbind.so use_first_pass
	auth        required      pam_deny.so
	
	account     required      pam_access.so
	account     required      pam_unix.so broken_shadow
	account     sufficient    pam_localuser.so
	account     sufficient    pam_succeed_if.so uid < 500 quiet
	account     [default=bad success=ok user_unknown=ignore] pam_krb5.so
	account     [default=bad success=ok user_unknown=ignore] pam_winbind.so
	account     required      pam_permit.so
	
	password    requisite     pam_cracklib.so try_first_pass retry=3 type=
	password    sufficient    pam_unix.so sha512 shadow nullok try_first_pass use_authtok
	password    sufficient    pam_krb5.so use_authtok
	password    sufficient    pam_winbind.so use_authtok
	password    required      pam_deny.so
	
	session     optional      pam_keyinit.so revoke
	session     required      pam_limits.so
	session     optional      pam_oddjob_mkhomedir.so umask=0077
	session     [success=1 default=ignore] pam_succeed_if.so service in crond quiet use_uid
	session     required      pam_unix.so
	session     optional      pam_krb5.so
	EOF

	rm -f /etc/pam.d/password-auth
	ln -s /etc/pam.d/system-auth-ac /etc/pam.d/password-auth
}

install_packages () 
{
	yum -y install ntp authconfig krb5-workstation pam_krb5 samba-common samba oddjob-mkhomedir sudo
}


start_services () 
{
	chkconfig oddjobd on
	chkconfig winbind on
	chkconfig nmb on
	chkconfig smb on
	chkconfig messagebus on
	service oddjobd restart 
	service nmb restart
	service winbind restart
	service smb restart
	service messagebus restart

}

join_domain () 
{
	echo
	echo "JOIN:"
	echo 
	echo "Here goes. Here's what should happen." 
	echo "You are trying to join the host $(hostname -f)" 
	echo "to the $(dnsdomainname | tr '[a-z]' '[A-Z]') domain." 
	echo
	local user_confirmed
	read -p "Everything look right? [y/N]: " user_confirmed
	case $user_confirmed in
		[yY])
			echo 
			echo "Okay. We're doing this." 
			read -p "Enter Domain Admin username [$(whoami)]: " adadmin
			if [[ -z $adadmin ]]; then 
				adadmin=$(whoami)
			fi
			net ads join $(dnsdomainname) -U $adadmin
			;;
		   *)
			echo 
			echo "Try again when you're ready."
			exit 1
			;;
	esac



}

warn_jerks () 
{
	echo
	echo
	echo "WARNING:"
	echo "This script will overwrite several system files." 
	echo "That's kind-of the point, but you should back up these"
	echo "files first:"
	echo "    /etc/krb5.conf"
	echo "    /etc/pam.d/system-auth"
	echo "    /etc/samba/smb.conf"
	echo "    /etc/nsswitch.conf"
	echo "    /etc/hosts" 
	echo
	echo "Back things up first. You have been warned."
	echo 
	echo "This is designed to run on CentOS 6.5. It will probably"
	echo "work on RHEL, too, but has not been tested." 
	echo
	echo "You're on your own if you don't use yum for package"
	echo "management. It's not hard. Good luck."
	echo 
	echo "Your hostname is $(hostname)."
	echo "That is how it will identify itself to AD and how"
	echo "other users will view it."
	echo 
	echo "You will be given the opportunity to change the"
	echo "hostname." 
	echo
	echo "Do you understand it's your fault if this script"
	echo "destroys your system and you don't have backups?"
	echo 

	read -p "I understand it's my fault if this breaks everything [y/N]: " disclaimed


	case $disclaimed in
		[yY])
			echo
			echo "Okay. Let's get started." 
			echo "-----------"
			echo
			;;
		   *)
			echo "That's a no, then." 
			exit 1
			;;
	esac
}

configure_hostname () 
{
	echo
	echo "HOSTNAME CONFIGURATION: "
	echo
	echo "Let's set our hostname. It should be the FQDN"
	echo "[host.addomain.tld] you want your machine to use"
	echo
	echo "Take care to set the host and domain name"
	echo "correctly. Weird Things will happen if not."
	echo
	read -p "Fully qualified hostname to use [$(hostname)]: " userinput

	if [[ ! -z $userinput ]];then
		hostname $userinput
		sed -i .adjoinsave -e \
			's/^127.0.0.1.*$/127.0.0.1  '$(hostname)' '$(hostname -s)' localhost localdomain localhost4 localhost4.localdomain/' \
			/etc/hosts
	fi 

}

script_main () 
{

	arg=$1
	

	case $arg in
		--really)
			warn_jerks
			configure_hostname
			install_packages
			configure_samba 
			configure_nsswitch
			configure_pam
			configure_kerberos
			join_domain
			start_services
			;;
		*)
			echo "DRY RUN: "
			echo "Adding host $(hostname -s)"
			echo "Would attempt to run: "
			echo "net ads join $(dnsdomainname) -U $(whoami)"
			echo "--You'll be prompted for a domain user" 
			echo "using kdc $(lookup_kdc)" 
			echo "add '--really' to actually do the join"
			;;
	esac

}

script_main $1
