#!/usr/bin/env python
# -*- coding: utf-8 -*-

__author__      = "Guillaume Blanco, Patrick Neto"
__copyright__   = "Copyright 2017, HEIG-VD"
__license__ 	= "GPL"
__version__ 	= "1.0"
__email__ 		= "guillaume.blanco@heig-vd.ch, patrick.neto@heig-vd.ch"
__status__ 		= "Prototype"

import hmac, hashlib

"""
Dérive des clés WPA avec la passphraswe et les infos du 4-way handshake

Calcule un MIC d'authentification (le MIC pour la transmission de données
utilise l'algorithme Michael. Dans ce cas-ci, l'authentification, on utilise
sha-1 pour WPA2 ou MD5 pour WPA)
"""
def customPRF512(key,A,B):
    blen = 64
    i    = 0
    R    = ''
    while i<=((blen*8+159)/160):
        hmacsha1 = hmac.new(key,A+chr(0x00)+B+chr(i),hashlib.sha1)
        i+=1
        R = R+hmacsha1.digest()
    return R[:blen]