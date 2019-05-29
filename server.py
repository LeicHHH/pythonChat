import socket,OpenSSL
from Crypto.Hash import SHA3_256,SHA384
from Crypto.Cipher import AES,PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes,new
from Crypto.Util.Padding import unpad,pad
from base64 import b64decode,b64encode
from json import loads,dumps

def listenServer(protocol):
    HOST = socket.gethostbyname(socket.gethostname())
    PORT = int(input("Server port: "))
    print("Server ip:" + HOST + "\nPort:" + str(PORT))
    if (protocol == 2):
        encryptionMode = int(input("(1) for AES (2) for RSA: "))
        if(encryptionMode == 2):
            hashMode = int(input("(1)SHA3-256 o (2)SHA384"))
            context = OpenSSL.SSL.Context(OpenSSL.SSL.TLSv1_2_METHOD)
            context.use_certificate_file('certificate.crt')
            context.use_privatekey_file('privateKey.key')
            s = socket.socket(socket.AF_INET,socket.SOCK_STREAM, 0)
            connection = OpenSSL.SSL.Connection(context,s)
            connection.bind((HOST, PORT))
            connection.listen(2)
            print("Waiting for connections...")
            conn, addr = connection.accept()
            print("Client: "+ str(addr[0]) + " connected")
            RSAkey = RSA.generate(1024,new().read)
            RSApubkey = RSAkey.publickey()
            conn.send(RSApubkey.export_key(format = "PEM", passphrase = None, pkcs = 1))
            print("Public key sent to client")
            pub_key = RSA.import_key(conn.recv(1024), passphrase=None)
            print("Public key received")
            if(hashMode == 1):
                print("[BYE] to exit the chat")
                while True:
                    data = conn.recv(512)
                    decrypted = PKCS1_OAEP.new(RSAkey,hashAlgo=SHA3_256).decrypt(data).decode()
                    if(decrypted == 'BYE'):
                        break
                    print("clientMessageTCP_RSA>>> " + decrypted)
                    message = input("serverMessageTCP_RSA>>>")
                    if(message == 'BYE'):
                        cipher = PKCS1_OAEP.new(pub_key,hashAlgo=SHA3_256)
                        conn.send(cipher.encrypt("BYE".encode()))
                        break
                    cipher = PKCS1_OAEP.new(pub_key,hashAlgo=SHA3_256)
                    ciphertext = cipher.encrypt(message.encode())
                    conn.send(ciphertext)
            else:
                print("[BYE] to exit the chat")
                while True:
                    data = conn.recv(512)
                    decrypted = PKCS1_OAEP.new(RSAkey,hashAlgo=SHA384).decrypt(data).decode()
                    if(decrypted == 'BYE'):
                        break
                    print("clientMessageTCP_RSA>>> " + decrypted)
                    message = input("serverMessageTCP_RSA>>>")
                    if(message == 'BYE'):
                        cipher = PKCS1_OAEP.new(pub_key,hashAlgo=SHA384)
                        conn.send(cipher.encrypt("BYE".encode()))
                        break
                    cipher = PKCS1_OAEP.new(pub_key,hashAlgo=SHA384)
                    ciphertext = cipher.encrypt(message.encode())
                    conn.send(ciphertext)
            main()
        else:
            key = input("Password:")
            context = OpenSSL.SSL.Context(OpenSSL.SSL.TLSv1_2_METHOD)
            context.use_certificate_file('certificate.crt')
            context.use_privatekey_file('privateKey.key')
            s = socket.socket(socket.AF_INET,socket.SOCK_STREAM, 0)
            connection = OpenSSL.SSL.Connection(context,s)
            connection.bind((HOST, PORT))
            connection.listen(2)
            print("Waiting for connections...")
            conn, addr = connection.accept()
            print("Client: "+ str(addr[0]) + " connected")
            print("[BYE] to exit the chat")
            while True:
                json_input = conn.recv(1024)
                b64 = loads(json_input)
                iv = b64decode(b64['iv'])
                ct = b64decode(b64['ciphertext'])
                cipher = AES.new(key.encode(),AES.MODE_CBC,iv=iv)
                pt = unpad(cipher.decrypt(ct),AES.block_size)
                if(pt.decode() == 'BYE'):
                    break
                print("clientMensajeTCP_AES>>>>>" + pt.decode())
                message = input("serverMessageTCP_AES>>>")
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
                conn.send(result.encode())
            main()
    else:
        key = input("Password:")
        print("[BYE] to exit the chat")
        while True:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.bind((HOST, PORT))
            conn,addr = s.recvfrom(1024)
            b64 = loads(conn)
            iv = b64decode(b64['iv'])
            ct = b64decode(b64['ciphertext'])
            cipher = AES.new(key.encode(),AES.MODE_CBC, iv)
            pt = unpad(cipher.decrypt(ct),AES.block_size)
            print("clientMessageUDP_AES>>> " + pt.decode())
            message = input("serverMessageUDP_AES>>>>")
            if(message == 'BYE'):
                break
            cipher = AES.new(key.encode(),AES.MODE_CBC)
            ct_bytes = cipher.encrypt(pad(message.encode(),AES.block_size))
            iv = b64encode(cipher.iv).decode('utf-8')
            ct = b64encode(ct_bytes).decode('utf-8')
            result = dumps({'iv':iv, 'ciphertext': ct})
            s.sendto(result.encode(),(addr[0],addr[1]))
            s.close()        
        main()

def main():
    protocol = int(input("Select (1)UDP or (2)TCP: "))
    listenServer(protocol)

if __name__ == "__main__":
    main()