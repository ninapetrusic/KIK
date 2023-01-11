#!/usr/bin/env python3

import pickle
import os
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.asymmetric import ec

class MessengerClient:
    """ Messenger client klasa

        Slobodno mijenjajte postojeće atribute i dodajte nove kako smatrate
        prikladnim.
    """

    def __init__(self, username, ca_pub_key):
        """ Inicijalizacija klijenta

        Argumenti:
        username (str) -- ime klijenta
        ca_pub_key     -- javni ključ od CA (certificate authority)

        """
        self.username = username
        self.ca_pub_key = ca_pub_key
        # Aktivne konekcije s drugim klijentima
        ## username:(njihov public, nas private)
        self.conns = {}
        # Inicijalni Diffie-Hellman par ključeva iz metode `generate_certificate`
        self.dh_key_pair = ()

    def generate_certificate(self):
        """ Generira par Diffie-Hellman ključeva i vraća certifikacijski objekt

        Metoda generira inicijalni Diffie-Hellman par kljuceva; serijalizirani
        javni kljuc se zajedno s imenom klijenta postavlja u certifikacijski
        objekt kojeg metoda vraća. Certifikacijski objekt moze biti proizvoljan (npr.
        dict ili tuple). Za serijalizaciju kljuca mozete koristiti
        metodu `public_bytes`; format (PEM ili DER) je proizvoljan.

        Certifikacijski objekt koji metoda vrati bit će potpisan od strane CA te
        će tako dobiveni certifikat biti proslijeđen drugim klijentima.

        """
        ## elliptic curve cryptography
        private_key = X25519PrivateKey.generate()
        public_key = private_key.public_key()
        self.dh_key_pair = (private_key, public_key)
        
        return (public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo), self.username)

    def receive_certificate(self, cert, signature):
        """ Verificira certifikat klijenta i sprema informacije o klijentu (ime
            i javni ključ)

        Argumenti:
        cert      -- certifikacijski objekt
        signature -- digitalni potpis od `cert`

        Metoda prima certifikacijski objekt (koji sadrži inicijalni
        Diffie-Hellman javni ključ i ime klijenta) i njegov potpis kojeg
        verificira koristeći javni ključ od CA i, ako je verifikacija uspješna,
        sprema informacije o klijentu (ime i javni ključ). Javni ključ od CA je
        spremljen prilikom inicijalizacije objekta.

        """
        (public_key, username) = cert
        self.ca_pub_key.verify(signature, pickle.dumps(cert), ec.ECDSA(hashes.SHA256()))
        
        ## inicijalni javni kljuc nekog usera i nas privatni za tog usera
        self.conns.update({username: (load_pem_public_key(public_key),self.dh_key_pair[0])})


    def send_message(self, username, message):
        """ Slanje poruke klijentu

        Argumenti:
        message  -- poruka koju ćemo poslati
        username -- klijent kojem šaljemo poruku `message`

        Metoda šalje kriptiranu poruku sa zaglavljem klijentu s imenom `username`.
        Pretpostavite da već posjedujete certifikacijski objekt od klijenta
        (dobiven pomoću `receive_certificate`) i da klijent posjeduje vaš.
        Ako već prije niste komunicirali, uspostavite sesiju tako da generirate
        nužne `double ratchet` ključeve prema specifikaciji.

        Svaki put kada šaljete poruku napravite `ratchet` korak u `sending`
        lanacu (i `root` lanacu ako je potrebno prema specifikaciji).  S novim
        `sending` ključem kriptirajte poruku koristeći simetrični kriptosustav
        AES-GCM tako da zaglavlje poruke bude autentificirano.  Ovo znači da u
        zaglavlju poruke trebate proslijediti odgovarajući inicijalizacijski
        vektor.  Zaglavlje treba sadržavati podatke potrebne klijentu da
        derivira novi ključ i dekriptira poruku.  Svaka poruka mora biti
        kriptirana novim `sending` ključem.

        Metoda treba vratiti kriptiranu poruku zajedno sa zaglavljem.

        """
        username_public_key = self.conns.get(username)[0]

        ## novi par
        private_key = X25519PrivateKey.generate()
        public_key = private_key.public_key()
        self.conns.update({username: (username_public_key,private_key)})

        root_key = private_key.exchange(username_public_key)
        derived_key = HKDF(algorithm=hashes.SHA256(), length=96, salt=None, info=b'handshake data').derive(root_key)
        
        root_key = derived_key[:32]
        send_key = derived_key[32:64]
        recv_key = derived_key[64:]

        ## enkripcija poruke
        aesgcm = AESGCM(send_key)
        nonce = os.urandom(16)
        data = bytes(message, 'utf-8')
        enc_mess = aesgcm.encrypt(nonce, data, None)

        ## nonce, kriptirana poruka i nas novi javni kljuc
        return (nonce, enc_mess, public_key)

    def receive_message(self, username, message):
        """ Primanje poruke od korisnika

        Argumenti:
        message  -- poruka koju smo primili
        username -- klijent koji je poslao poruku

        Metoda prima kriptiranu poruku od klijenta s imenom `username`.
        Pretpostavite da već posjedujete certifikacijski objekt od klijenta
        (dobiven pomoću `receive_certificate`) i da je klijent izračunao
        inicijalni `root` ključ uz pomoć javnog Diffie-Hellman ključa iz vašeg
        certifikata.  Ako već prije niste komunicirali, uspostavite sesiju tako
        da generirate nužne `double ratchet` ključeve prema specifikaciji.

        Svaki put kada primite poruku napravite `ratchet` korak u `receiving`
        lanacu (i `root` lanacu ako je potrebno prema specifikaciji) koristeći
        informacije dostupne u zaglavlju i dekriptirajte poruku uz pomoć novog
        `receiving` ključa. Ako detektirate da je integritet poruke narušen,
        zaustavite izvršavanje programa i generirajte iznimku.

        Metoda treba vratiti dekriptiranu poruku.

        """
        ## nismo dobili certifikat ili nije bio valjan
        if username not in self.conns.keys():
            raise Exception

        ## ponovljena poruka
        username_public_key = message[2]
        if username_public_key == self.conns.get(username)[0]:
            raise Exception
        else:
            private_key = self.conns.get(username)[1]
            self.conns.update({username: (username_public_key,private_key)})
        ## nonce za aesgcm
        nonce = message[0]
        enc_mess = message[1]

        private_key = self.conns.get(username)[1]
        root_key = private_key.exchange(username_public_key)
        derived_key = HKDF(algorithm=hashes.SHA256(), length=96, salt=None, info=b'handshake data').derive(root_key)
        
        root_key = derived_key[:32]
        recv_key = derived_key[32:64]
        send_key = derived_key[64:]

        aesgcm = AESGCM(recv_key)
        try:
            plain_message = aesgcm.decrypt(nonce, enc_mess, None)
        except Exception:
            raise Exception
        plain_message = plain_message.decode('utf-8')

        return (plain_message)
        

def main():
    pass

if __name__ == "__main__":
    main()
