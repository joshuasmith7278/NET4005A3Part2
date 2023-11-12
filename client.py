import socket
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
import os





def client():
    host = socket.gethostname()
    port = 6969


    ##Generate RSA Key for Client Private Key
    """
    key = RSA.generate(2048)
    f = open("client_key.pem", "wb")
    f.write(key.export_key("PEM"))
    f.close()

    f = open("client_public.pem", "wb")
    f.write(key.public_key().export_key("PEM"))
    f.close()
    
    
    """
     

    ##Gather RSA keys for local files 
    with open("client_key.pem", "rb") as f:
        private_key = RSA.import_key(f.read())

    
    with open("server_public.pem", "rb") as f:
        server_publickey = RSA.import_key(f.read())
    


    client_socket = socket.socket()
    client_socket.connect((host, port))


    message = input("->")


    while message.lower().strip() != 'byte':
        

        print("\n------- Symm Encrypted Message : -------")

        ##Hash the original message using SHA256
        ##Sign the Hash with CLIENT PRIVATE KEY to ensure Client signed it
        hash_value = SHA256.new(message.encode())
        signature = PKCS1_v1_5.new(private_key).sign(hash_value)
        signed_message = str(signature) + message
        print("Signed Message : " + str(signed_message))



        ##Encrypt the Signed Message with a secret key
        ##The secret key is a AES 16 Byte symmetric key
        secret_key = get_random_bytes(16)
        cipher = AES.new(secret_key, AES.MODE_ECB)
        ciphertext = cipher.encrypt(pad(signed_message.encode(), 16))
        print("Encypt Message : " + str(ciphertext))

        print("\n------------ Asymm Enc ------------")
       ##Encrypt the Secret key with the Servers PUBLIC KEY
       ##This allows ONLY the server to decrypt and use the secret key
        cipher_seckey = PKCS1_OAEP.new(server_publickey)
        ciphertext_seckey = cipher_seckey.encrypt(secret_key)

        print("\nPlaintext secret key :")
        print(secret_key)

        print("\nAsymm Encrypted Key : ")
        print(ciphertext_seckey)


        enc_message = ciphertext + ciphertext_seckey

        ##Send the message signature and encryption to the server
        client_socket.send(ciphertext)
        client_socket.send(ciphertext_seckey)

        

        data = client_socket.recv(1024).decode()
        print('\nRecieved from server: ' + data)

        message = input("->")

    client_socket.close()

if __name__ == '__main__':
    client()