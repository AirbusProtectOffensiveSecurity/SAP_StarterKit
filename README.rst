SAP
===

Comptes sap.com
---------------

Deux types de comptes sap.com : 

- P-User : Utilisateur public, qui peut participer à la communauté en ligne
  mais n'a pas accès à toutes les ressources.

- S-User : Compte des servives utilisé par les clients et les partenaires SAP.

Permet notamment de télécharger des softs SAP comme le NW RFC SDK. Ce type de
compte est payant. 

SAP Security
------------

- SAP Security Patch Day

Beaucoup de CVEs sont publiées tous les mois (notamment venant d'Onapsys). SAP 
a son security patch day tous les mois et fournit des bulletins de sécurité 
les vulns découvertes: `ici <https://wiki.scn.sap.com/wiki/display/Security/>`__ 
et `ici <https://wiki.scn.sap.com/wiki/display/Security/Security+Notes+Webinar+-+2023-02>`__.

- `SAP ABAP Transactions codes related to SAP Security <https://wiki.scn.sap.com/wiki/display/Security/List+of+ABAP-transaction+codes+related+to+SAP+security>`__

Tools
-----

Librairies et outils utiles
***************************

- SAP GUI: Téléchargeable gratuitement `ici <https://developers.sap.com/trials-downloads.html>`__

  - Credentials trouvées sur bugmenot.com : enjeviesvvnofrylla@rffff.net / sapppret2-12U
  - Extraire les sources : unrar x SAP_GUI_for_Java.rar
  - Installer : java -jar PlatinGUI-Linux-7.70rev1.jar
  - Démarrer : guistart conn=/H/<URL>/S/<PORT>

- Addon Nmap pour la reconnaissance de proto SAP (nmap-erpscan) : 

  .. code-block:: bash

  	git clone https://github.com/gelim/nmap-erpscan.git
  	cd nmap-erpscan
  	NMAPDIR=. nmap -p $(sap_ports.py) <IP> -sV --open

- Dissecteur wireshark pour les protocole SAP

  .. code-block:: bash 

	git clone https://gitlab.com/wireshark/wireshark && cd wireshark
  	git checkout release-3.6
	git clone https://github.com/SecureAuthCorp/SAP-Dissection-plug-in-for-Wireshark/ plugins/epan/sap
  	git apply plugins/epan/sap/wireshark-release-3.6.patch
  	mkdir -p build && cd build
  	sudo apt install glib2-devel libglib2.0-dev libgcrypt20-dev libc-ares-dev qtbase5-dev libqt5svg5-dev qttools5-dev qtmultimedia5-dev
  	cmake .. && make && sudo make install

- `Plugin <https://saplearners.com/how-to-connect-sap-hana-cloud-from-dbeaver/>`__ 
  dbeaver pour SAP HANA 
- pysap -> lib python sans dépendance payante, fournie avec plein de scripts /
  poc utiles pour différents services SAP (bruteforce, enum...). 
- SAP RFC SDK: Librairie C/C++ pour se connecter aux systèmes SAP. Nécéssite un
  compte S-User (payant). 
- PyRFC: Python binding du SAP RFC SDK. Nécéssite un compte S-User (payant). 


Exploits toolkits
*****************

- RFCpwn: An SAP enumeration and exploitation toolkit using SAP RFC calls --> Nécéssite SAP RFC GUI. 
- SAP_GW_RCE_exploit (`<https://github.com/chipik/SAP_GW_RCE_exploit>`__)
- SAP_RECON (PoC for CVE-2020-6287, CVE-2020-6286): `<https://github.com/chipik/SAP_RECON>`__
- Nuclei Template  CVE-2022-22536 `<https://github.com/projectdiscovery/nuclei-templates/blob/master/cves/2022/CVE-2022-22536.yaml>`__
- Exploit CVE-2020-6287 `<https://github.com/murataydemir/CVE-2020-6287>`__
- Open Redirect POC `<https://wiki.scn.sap.com/wiki/display/ABAPConn/The+logoff+parameter+redirecturl+is+marked+as+a+security+vulnerability>`__


Metasploit pour SAP
-------------------

Beaucoup de modules metasploit existent:
  - service discovery
  - public infos
  - sap management console scanners
  - brute-forcing credentials, prefer bruteforcing on Management Console rather 
    than Web UI


.. code-block:: bash

	msfconsole -q -x 'use auxiliary/scanner/sap/sap_service_discovery ; set RHOSTS $URL ; run'
	msfconsole -q -x 'use auxiliary/scanner/sap/sap_mgmt_con_getprocesslist ; set RHOSTS $URL ; run'


Wordlist
--------

Credentials SAP par défaut : voir :download:`ce fichier <sap_creds.txt>`.


Github & whitepapers
--------------------

- `SAP security cheatsheet <https://github.com/Jean-Francois-C/SAP-Security-Audit/blob/master/SAP%20security%20audit%20and%20penetration%20test>`__
- `SAP Security Assessment Methodology <https://niiconsulting.com/checkmate/2021/01/sap-security-assessment-methodology-part-3-credential-centric-attack-vectors/>`__
- `SAP Default Credentials <https://protect4s.com/wp-content/uploads/2017/05/CYBSEC_16_An-easy-way-into-your-SAP-systems_V3.0.pdf>`__
- `HackTricks <https://book.hacktricks.xyz/network-services-pentesting/pentesting-sap>`__
- `My SAP Adventure <https://github.com/shipcod3/mySapAdventures>`__
- `SAP Gateway to Heaven <https://github.com/msuiche/OPCDE/blob/master/2019/Emirates/(SAP)%20Gateway%20to%20Heaven%20-%20Dmitry%20Chastuhin%2C%20Mathieu%20Geli/(SAP)%20Gateway%20to%20Heaven.pdf>`__
- `SAP development tools <https://tools.eu1.hana.ondemand.com/>`__

