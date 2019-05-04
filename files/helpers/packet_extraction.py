#!/usr/bin/env python
# -*- coding: utf-8 -*-

__author__      = "Guillaume Blanco, Patrick Neto"
__copyright__   = "Copyright 2017, HEIG-VD"
__license__ 	= "GPL"
__version__ 	= "1.0"
__email__ 		= "guillaume.blanco@heig-vd.ch, patrick.neto@heig-vd.ch"
__status__ 		= "Prototype"

from scapy.all import *
from binascii import a2b_hex, b2a_hex
from pbkdf2_math import pbkdf2_hex
from numpy import array_split
from numpy import array
from custom_functions import customPRF512
import hmac, hashlib

# Constantes utilisées pour la dérivation de clés
NB_HASHS = 4096
PBDF_KEY_LENGTH = 32 #valeur en octets

# Lecture du fichier de capture des paquets
wpa=rdpcap("wpa_handshake.cap") 

# Paramètres important pour la dérivation de clé
passPhrase  = "actuelle"
A           = "Pairwise key expansion" #string utilisée pour la fonction pseudo-aléatoire
ssid        =  wpa[0].info  #"SWI"
APmac       =  a2b_hex(wpa[1].addr3.replace(':', '')) #a2b_hex("cebcc8fdcab7")
Clientmac   =  a2b_hex(wpa[1].addr1.replace(':', '')) #a2b_hex("0013efd015bd")

# Authenticator and Supplicant Nonces
ANonce      = a2b_hex(str(wpa[5][Raw]).encode("HEX")[26:90]) #a2b_hex("90773b9a9661fee1f406e8989c912b45b029c652224e8b561417672ca7e0fd91")
SNonce      = a2b_hex(str(wpa[6][Raw]).encode("HEX")[26:90]) # a2b_hex("7b3826876d14ff301aee7c1072b5e9091e21169841bce9ae8a3f24628f264577")

# This is the MIC contained in the 4th frame of the 4-way handshake
# When attacking WPA, we would compare it to our own MIC calculated using passphrases from a dictionary
micToTest = str(wpa[8][Raw]).encode("hex")[154:186]

B           = min(APmac,Clientmac)+max(APmac,Clientmac)+min(ANonce,SNonce)+max(ANonce,SNonce)#utilisée dans la fonction pseudo-aléatoire
data        = a2b_hex("0103005f02030a0000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000") #cf "Quelques détails importants" dans la donnée 
