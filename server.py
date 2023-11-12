import socket
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256
from Crypto.Util.Padding import unpad


def server():
    host = socket.gethostname()
    port = 6969

    ##Generate RSA Private Key for Client

    """
    key = RSA.generate(2048)
    f = open("server_key.pem", "wb")
    f.write(key.export_key("PEM"))
    f.close()

    f = open("server_public.pem", "wb")
    f.write(key.public_key().export_key("PEM"))
    f.close()
    
    
    """
    


    ##Gather RSA Keys from local files.
    ##Server Private Key and Client Public Key
    with open("server_key.pem", "rb") as f:
        private_key = RSA.import_key(f.read())  

        
    with open("client_public.pem", "rb") as f:
        client_publickey = RSA.import_key(f.read())

    
   

    server_socket = socket.socket()
    server_socket.bind((host, port))

    server_socket.listen(1)
    conn, address = server_socket.accept()
    print("Connection from: " + str(address))


    while True:
        ##Recieve the first 256 bytes for the signature
        ##The rest of the message is the encryption
        

        encryption = conn.recv(1024)
        if not encryption:
            break
        enc_seckey = conn.recv(1024)
        if not enc_seckey:
            break
        
       
        ##This is the Asymmetric encryped key
        ##First must decrypet the Asymmetric Enc to get
        ##the secret key. Use PRIVATE Key to decrypt
        print("\n--------- Decrypting Secret Key ------------")
        print("Asymm Enc Key : " + str(enc_seckey))
        seckey_cipher = PKCS1_OAEP.new(private_key)
        seckey_plaintext = seckey_cipher.decrypt(enc_seckey)
        print("Plaintext sec key : " + str(seckey_plaintext))


        ##This is the Symmetric encrypted message   
        print("\n --------- Decrypting the Secret Message ------------")
        print("\nSymmetric Enc Message : " + str(encryption))

        cipher = AES.new(seckey_plaintext, AES.MODE_ECB)
        message_plaintext = unpad(cipher.decrypt(encryption), 16)

        print("\nMessage Plaintext: \n")
        print(message_plaintext.decode())





        ##Create a cipher with SERVER PRIVATE KEY
        ##Decrypt the encrypted message with the cipher
       

        data = "Recieved"

        
        conn.send(data.encode())

    conn.close()


if __name__ == '__main__':
    server()