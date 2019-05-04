#!/usr/bin/env python
# -*- coding: utf-8 -*-

__author__      = "Guillaume Blanco, Patrick Neto"
__copyright__   = "Copyright 2017, HEIG-VD"
__license__ 	= "GPL"
__version__ 	= "1.0"
__email__ 		= "guillaume.blanco@heig-vd.ch, patrick.neto@heig-vd.ch"
__status__ 		= "Prototype"

from helpers.packet_extraction import * # L'extraction des valeurs de la capture de paquet est ici

# Affichage des valeurs pertinentes pour l'attaque
print "\n\nValues used to derivate keys"
print "============================"
print "Passphrase:\t", passPhrase
print "SSID:\t\t", ssid,"\n"
print "AP Mac:\t\t", b2a_hex(APmac)
print "CLient Mac:\t", b2a_hex(Clientmac)
print "AP Nonce:\t", b2a_hex(ANonce)    #b2a_hex(ANonce),"\n"
print "Client Nonce:\t",b2a_hex(SNonce) #b2a_hex(SNonce),"\n"

# Passphrase hashée 4096 fois pour obtenir une Pairwise Master Key
pmk = pbkdf2_hex(passPhrase, ssid, NB_HASHS, PBDF_KEY_LENGTH)

# Passage de la Pairwise Master Key dans une fonction pseudo-aléatoire,
# afin d'obtenir la Pairwise Transient Key
ptk = customPRF512(a2b_hex(pmk),A,B)

#Calcul du MIC sur le payload (algo Michael)- La PTK est, en fait, KCK|KEK|TK|MICK
mic = hmac.new(ptk[0:16],data,hashlib.sha1)

# Affichage des différentes clés et contrôles d'intégrité, suite à la phase
# de dérivation de clé
print "\nResults of the key expansion"
print "============================="
print "PMK:\t\t",pmk
print "PTK:\t\t",b2a_hex(ptk)
print "KCK:\t\t",b2a_hex(ptk[0:16])
print "KEK:\t\t",b2a_hex(ptk[16:32])
print "TK:\t\t",b2a_hex(ptk[32:48])
print "MICK:\t\t",b2a_hex(ptk[48:64])
print "MIC:\t\t", mic.hexdigest()