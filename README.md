# pythonChat
This is my implementation of a python server-client secure chat using TCP and UDP, encryption (AES,RSA), transport layer security (TLS), and hashing algorithms. 

## Getting Started

For testing you have to provide certificate and private key for TLS in the same folder of server code named 'certificate.crt' and 'privateKey.key' for UDP is not necesary.


### Prerequisites
```sh
$ pip install pycrypto

$ pip install pyopenssl

$ pip install pyinstaller
```

### Running the tests
```sh

$ pyinstaller --onefile client.py

$ pyinstaller --onefile server.py

```

### Built With
* pyCrypto 

* OpenSSL

### Authors
Sebastian Mahuzier.
