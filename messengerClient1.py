#!/usr/bin/env python3
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

class MessengerClient:
    """ Messenger client class

        Feel free to modify the attributes and add new ones as you
        see fit.

    """
    ## salt za hkdf
    salt = os.urandom(16)

    def __init__(self, username, max_skip=10):
        """ Initializes a client

        Arguments:
        username (str) -- client name
        max_skip (int) -- Maximum number of message keys that can be skipped in
                          a single chain

        """
        self.username = username
        # Data regarding active connections.
        self.conn = {}
        # Maximum number of message keys that can be skipped in a single chain
        self.max_skip = max_skip
        ## broj poslanih i primljenih poruka
        self.mess_send = {}
        self.mess_recv = {}
        ## kljucevi za preskocene poruke
        self.keys = {}

    def add_connection(self, username, chain_key_send, chain_key_recv):
        """ Add a new connection

        Arguments:
        username (str) -- user that we want to talk to
        chain_key_send -- sending chain key (CKs) of the usernamehttps://signal.org/docs/specifications/doubleratchet
        chain_key_recv -- receiving chain key (CKr) of the username

        """
        self.conn.update({username: (chain_key_send,chain_key_recv)})
        self.mess_send.update({username:0})
        self.mess_recv.update({username:0})

        ##raise NotImplementedError()

    def send_message(self, username, message):
        """ Send a message to a user

        Get the current sending key of the username, perform a symmetric-ratchet
        step, encrypt the message, update the sending key, return a header and
        a ciphertext.

        Arguments:
        username (str) -- user we want to send a message to
        message (str)  -- plaintext we want to send

        Returns a ciphertext and a header data (you can use a tuple object)

        """
        ## update broj poslanih poruka useru
        value = self.mess_send.get(username) + 1
        self.mess_send.update({username: value})
        ## username send, username recv
        (chain_key_send,chain_key_recv) = self.conn.get(username)
        ## novi message i chain key
        hkdf = HKDF(algorithm=hashes.SHA256(), length=64, salt=MessengerClient.salt, info=None)
        output = hkdf.derive(chain_key_recv)
        chain_key_recv = output[:32]
        message_key = output[32:]
        ## AES-GCM encrypt
        aesgcm = AESGCM(message_key)
        nonce = os.urandom(16)
        data = bytes(message, 'utf-8')
        enc_mess = aesgcm.encrypt(nonce, data, None)

        ## update chain kljuceve
        self.conn.update({username: (chain_key_send, chain_key_recv)})
        
        ## return header and cipher
        return (value, nonce, enc_mess)

    def receive_message(self, username, message):
        """ Receive a message from a user

        Get the username connection data, check if the message is out-of-order,
        perform necessary symmetric-ratchet steps, decrypt the message and
        return the plaintext.

        Arguments:
        username (str) -- user who sent the message
        message        -- a ciphertext and a header data

        Returns a plaintext (str)

        """
        ## update broj primljenih poruka od usera
        value = self.mess_recv.get(username) + 1
        self.mess_recv.update({username: value})
        ## check out of order
        n = message[0]
        (chain_key_send,chain_key_recv) = self.conn.get(username)
        if value < n:
            i = 0
            while i < self.max_skip and value + i != n:
                ## spremanje preskocenih
                hkdf = HKDF(algorithm=hashes.SHA256(), length=64, salt=MessengerClient.salt, info=None)
                output = hkdf.derive(chain_key_send)
                chain_key_send = output[:32]
                message_key = output[32:]
                self.keys.update({(username,value + i): message_key})
                i += 1
            hkdf = HKDF(algorithm=hashes.SHA256(), length=64, salt=MessengerClient.salt, info=None)
            output = hkdf.derive(chain_key_send)
            chain_key_send = output[:32]
            message_key = output[32:]
        else:
            ## ako je bio preskocen
            if self.keys.get((username,n)):
                message_key = self.keys.pop((username,n))
            else:
                ## novi
                hkdf = HKDF(algorithm=hashes.SHA256(), length=64, salt=MessengerClient.salt, info=None)
                output = hkdf.derive(chain_key_send)
                chain_key_send = output[:32]
                message_key = output[32:]
        ## AES-GCM decrypt
        aesgcm = AESGCM(message_key)
        nonce = message[1]
        cypher = message[2]

        plain_message = aesgcm.decrypt(nonce, cypher, None)
        plain_message = plain_message.decode('utf-8')
        
        self.conn.update({username: (chain_key_send,chain_key_recv)})
        ## return 
        return plain_message
