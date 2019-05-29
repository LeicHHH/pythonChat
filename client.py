import socket,OpenSSL
from Crypto.Hash import SHA3_256,SHA384
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES,PKCS1_OAEP
from Crypto.Util.Padding import pad,unpad
from Crypto.Random import new
from base64 import b64encode,b64decode
from json import dumps,loads

def clientServer(protocol):
    HOST = input("Server IP: ")
    PORT = int(input("Sever Port: "))
    print("Server ip:" + HOST + "\nPort:" + str(PORT))
    if (protocol == 2):
        encryptionMode = int(input("(1) for AES (2) for RSA: "))
        if(encryptionMode == 2):
            hashMode = int(input("(1)SHA3-256 o (2)SHA384: "))
            context = OpenSSL.SSL.Context(OpenSSL.SSL.TLSv1_2_METHOD)
            s = socket.socket(socket.AF_INET,socket.SOCK_STREAM, 0)
            connection = OpenSSL.SSL.Connection(context,s)
            connection.connect((HOST,PORT))
            RSAkey = RSA.generate(1024,new().read)
            RSApubkey = RSAkey.publickey()
            connection.send(RSApubkey.export_key(format = "PEM", passphrase = None, pkcs = 1))
            print("PubKey Sent")
            pub_key = RSA.import_key(connection.recv(1024), passphrase=None)
            print("PubKey received")
            if(hashMode == 1):
                print("[BYE] to exit the chat")
                while True:
                    message = input("clientMessageTCP_RSA>>>: ")
                    if(message == 'BYE'):
                        cipher = PKCS1_OAEP.new(pub_key,hashAlgo=SHA3_256)
                        connection.send(cipher.encrypt("BYE".encode()))
                        break
                    cipher = PKCS1_OAEP.new(pub_key,hashAlgo=SHA3_256)
                    ciphertext = cipher.encrypt(message.encode())
                    connection.sendall(ciphertext)
                    data = connection.recv(512)
                    decrypted = PKCS1_OAEP.new(RSAkey,hashAlgo=SHA3_256).decrypt(data).decode()
                    if(decrypted == 'BYE'):
                        break
                    print("serverMessageTCP_RSA>>> " + decrypted)
            else:
                print("[BYE] to exit the chat")
                while True:
                    message = input("clientMessageTCP_RSA>>>: ")
                    if(message == 'BYE'):
                        cipher = PKCS1_OAEP.new(pub_key,hashAlgo=SHA384)
                        connection.send(cipher.encrypt("BYE".encode()))
                        break
                    cipher = PKCS1_OAEP.new(pub_key,hashAlgo=SHA384)
                    ciphertext = cipher.encrypt(message.encode())
                    connection.sendall(ciphertext)
                    data = connection.recv(512)
                    decrypted = PKCS1_OAEP.new(RSAkey,hashAlgo=SHA384).decrypt(data).decode()
                    if(decrypted == 'BYE'):
                        break
                    print("serverMessageTCP_RSA>>> " + decrypted)
            main()
        else:
            key = input('Server Password: ')
            context = OpenSSL.SSL.Context(OpenSSL.SSL.TLSv1_2_METHOD)
            s = socket.socket(socket.AF_INET,socket.SOCK_STREAM, 0)
            connection = OpenSSL.SSL.Connection(context,s)
            connection.connect((HOST,PORT))
            print("[BYE] to exit the chat")
            while True:
                message = input("clientMessageTCP_AES>>>: ")
                if(message == 'BYE'):
                    cipher = AES.new(key.encode(),AES.MODE_CBC)
                    ct_bytes = cipher.encrypt(pad('BYE'.encode(),AES.block_size))
                    iv = b64encode(cipher.iv).decode('utf-8')
                    ct = b64encode(ct_bytes).decode('utf-8')
                    result = dumps({'iv':iv, 'ciphertext': ct})
                    connection.send(result.encode())
                    break
                cipher = AES.new(key.encode(),AES.MODE_CBC)
                ct_bytes = cipher.encrypt(pad(message.encode(),AES.block_size))
                iv = b64encode(cipher.iv).decode('utf-8')
                ct = b64encode(ct_bytes).decode('utf-8')
                result = dumps({'iv':iv, 'ciphertext': ct})
                connection.send(result.encode())
                json_input = connection.recv(1024)
                b64 = loads(json_input)
                iv = b64decode(b64['iv'])
                ct = b64decode(b64['ciphertext'])
                cipher = AES.new(key.encode(),AES.MODE_CBC,iv=iv)
                pt = unpad(cipher.decrypt(ct),AES.block_size)
                if(pt.decode() == 'BYE'):
                    break
                print("serverMensajeTCP_AES>>>>>" + pt.decode())
            main()
    else:
        key = input("Server Password:")
        print("[BYE] to exit the chat")
        while True:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            message = input("clientMessageUDP_AES>>> ")
            if(message == 'BYE'):
                break
            cipher = AES.new(key.encode(),AES.MODE_CBC)
            ct_bytes = cipher.encrypt(pad(message.encode(),AES.block_size))
            iv = b64encode(cipher.iv).decode('utf-8')
            ct = b64encode(ct_bytes).decode('utf-8')
            result = dumps({'iv':iv, 'ciphertext': ct})
            s.sendto(result.encode(),(HOST,PORT))
            conn = s.recvfrom(1024)
            b64 = loads(conn[0])
            iv = b64decode(b64['iv'])
            ct = b64decode(b64['ciphertext'])
            cipher = AES.new(key.encode(),AES.MODE_CBC, iv)
            pt = unpad(cipher.decrypt(ct),AES.block_size)
            print("serverMessageUDP_AES>>> " + pt.decode())
            s.close()
        main()

def main():
    protocol = int(input("Select (1)UDP o (2)TCP: "))
    clientServer(protocol)

if __name__ == "__main__":
    main()