#!interpreter

"""
This program is designed to provide a web GUI to decrypt encrypted messages. 
"""

# Built-in/Generic Imports
import sys
from datetime import datetime
import base64

# Libraries
import cryptography
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet, InvalidToken
from flask import Flask, render_template, flash, request
from wtforms import Form, TextField, TextAreaField, validators, StringField, SubmitField

__author__ = 'IncognitoCoding'
__copyright__ = 'Copyright 2021, http_info_decryptor'
__credits__ = ['IncognitoCoding', 'Monoloch', 'tyler-durden-soap']
__license__ = 'GPL'
__version__ = '1.0'
__maintainer__ = 'IncognitoCoding'
__status__ = 'Development'


# Coordinate calls to all processing functions
def decrypt_info(encryption_password, random_salt, unconverted_encrypted_info):
    """[summary]

    Args:
        encryption_password (str): password used to encrypt the info
        random_salt (bytes): random salt string used to encrypt the info
        unconverted_encrypted_info (str): encrypted info in bytes format, but sent as a string from the web

    Returns:
        str: decrypted info
    """

    # Varifies encrypted info is not empty
    if unconverted_encrypted_info:
        
        try:

            # Verifies the user entered the info in bytes format.
            # The input entry will strip away the ability for python to recognize the entry in bytes.
            if unconverted_encrypted_info[:2] == "b'":

                # Strips the bytes section off the input.
                # Removes first 2 characters.
                unconverted_encrypted_info = unconverted_encrypted_info[2:]
                # Removes last character.
                unconverted_encrypted_info = unconverted_encrypted_info[:-1]
                
                # Re-encodes the info.
                encrypted_info = unconverted_encrypted_info.encode()

                # Varifies the info being sent is in bytes.
                if isinstance(encrypted_info, (bytes, bytearray)): 

                    # Calls function decrypt the info.
                    # Converting the pre-defined encryption password to bytes.
                    password = encryption_password.encode()  

                    # Setting random salt string that is a (byte) used to help protect from dictionary attacks.
                    # The salt string is randomly generated on the initial setup but static after the initial setup.
                    salt = random_salt

                    # Calling function to derive a cryptographic key from a password.
                    kdf = PBKDF2HMAC(
                        algorithm=hashes.SHA256(), # An instance of HashAlgorithm
                        length=32, # The desired length of the derived key in bytes. Maximum is (232 - 1)
                        salt=salt, # Secure values [1] are 128-bits (16 bytes) or longer and randomly generated
                        iterations=100000, # The number of iterations to perform of the hash function
                        backend=default_backend() # An optional instance of PBKDF2HMACBackend
                    )

                    # Encoding the string using the pre-defined encryption password and the cryptographic key into the binary form.
                    key = base64.urlsafe_b64encode(kdf.derive(password))

                    # Creating a symmetric authenticated cryptography (secret key).
                    f = Fernet(key)

                    # Decrypts the info.
                    decrypted_info = f.decrypt(encrypted_info)

                    # Converts bytes to Unicode string.
                    decrypted_info = decrypted_info.decode('utf-8','strict')
      
                    return (f'Successfully decrypted info. Result = {decrypted_info}')

                else:
                    return (f'The encrypted info is not in bytes. The info did not unencrypt. Unencrypted Info = {encrypted_info}')

            else:
                return (f'The encrypted info is not in bytes. The info did not unencrypt. Unencrypted Info = {unconverted_encrypted_info}')

        except Exception as e: 
            return (f'{e}')

        
    else:
        return (f'No encrypted info value has been provided. The info did not unencrypt.')

# Main function
def start_decryptor_site(encryption_password, random_salt, debug_option):
    """
    Starts the decryptor website.

    Args:
        encryption_password (str): password used to encrypt the info
        random_salt (bytes): random salt string used to encrypt the info
        debug_option (bool): debugging option

    Returns:
        template: information displayed back to the web site
    """

    # Environment Options.
    DEBUG = debug_option
    
    http_info_decryptor = Flask(__name__)

    class ReusableForm(Form):
        name = TextField('Name:', validators=[validators.required()])
        
        @http_info_decryptor.route('/')
        def my_form():
            return render_template('decrypt.html')

        @http_info_decryptor.route('/', methods=['POST'])
        def my_form_post():
            # Requests input.
            encrypted_info = request.form['text']

            # Calling function to decrypt the encrypted info.
            processed_text = decrypt_info(encryption_password, random_salt, encrypted_info)

            # Returns values to web.
            return render_template('decrypt.html', processed_text=processed_text)

    http_info_decryptor.run(host='0.0.0.0')


def main(encryption_password, random_salt, debug_option):

    # Starts up the decryptor site.
    start_decryptor_site(encryption_password, random_salt, debug_option)


# Use when running standalone.
if __name__ == "__main__":

    print('# ' + '=' * 85)
    print('Author: ' + __author__)
    print('Copyright: ' + __copyright__)
    print('Credits: ' + ', '.join(__credits__))
    print('License: ' + __license__)
    print('Version: ' + __version__)
    print('Maintainer: ' + __maintainer__)
    print('Status: ' + __status__)
    print('# ' + '=' * 85)

    # Password used for encryption.
    encryption_password = 'ChagePassword1'
    # Random salt used for encryption.
    random_salt = b'ChangeME'
    # Debug otpion.
    debug_option = False

    # Calls main function to start the web GUI.
    main(encryption_password, random_salt, debug_option)




