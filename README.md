# Plugboard-Proxy

Pbproxy is used to act as a reverse proxy for a service. This is accomplished by running the program with -l flag. Also, a file containing the passphrase must be provided to encrypt/decrypt the data between connections and this needs to be passed using the -p flag. The destination host and port are the other mandatory arguments to the program.

The program can be run using the below formats in server/client mode : 

1. When listening to incoming client connections :

	=> go run pbproxy.go -l <proxyPort> -p <passphraseFile> <destination> <port>

	Examples : go run pbproxy.go -l 2222 -p pwdFile.txt localhost 22
		   go run pbproxy.go -l 2222 -p pwdFile.txt localhost 5555	

2. When running the client program :

	=> go run -p pwdFile.txt <destination> <port>
	
	Examples : go run pbproxy.go -p pwdFile.txt localhost 2222
		  ssh -o "ProxyCommand go run pbproxy.go -p pwdFile.txt 172.24.18.193 2222" amogh@localhost


There's also a help command available and can be accessed using : 

=> go run pbproxy.go -help                                                                                                                                                                                                     

  -l string
        Specify the listening port which serves as reverse proxy
  -p string
        File containing the ASCII text keyphrase 


# Logic 

Here, I'm accepting the incoming connections from the client and also creating a new connection to the service for the particular connection to enable full duplex mode. Also, since the proxy should handle multiple connections, I've created infinite loop for that. The service should be up and running first.
I'm copying the data from between the connection form client-proxy and proxy-service. The data is encrypted using the passphrase from the file using AES-256 in GCM mode in encrypt function and sent to the client where pbproxy first decrypts it using the decrypt function and then prints to console output.
In the current implementation if the passphrase file is provided and yet the file is empty, then an error is thrown. On the client side, the data is accepted and encrypted using the passphrase provided in the file using AES-256 in GCM mode. Then the data is sent to service from service, where pbproxy decrypts it. For encryption, I am using a AES 256 encryption using randomized salt and nonce. The nonce(12 bytes) and salt(32 bytes) are appended to the encrypted data where it is fragmented on the decryption side and used for decrpytion.
Also, I have made few design considerations, first, the client is set a deadline of 60 seconds to respond, after which read and write operations have incremental deadlines. This is to handle the case of client to proxy connection being open while the proxy and server connection is refused. Then the client server connection, times out. Pbproxy can handle multiple clients.

# Sample outputs

1. I've attached the server.png and client.png files where I'm running the netcat service at port 5555 and client connects to it using 2222.
2. I've attached another set of outputs, client_ssh and server_ssh where pbproxy listens at port 2222 and relays traffic to port 22 (ssh). So client can ssh was able to ssh to service machine.


# References

Posts related to netcat implmentation in Go : 
1. https://medium.com/@yanzay/implementing-simple-netcat-using-go-bbab37507635
2. https://dddpaul.github.io/blog/2016/08/30/gonc/

Posts related to encrpytion and decryption in Go:
3. https://www.golangprograms.com/data-encryption-with-aes-gcm.html
4. https://www.thepolyglotdeveloper.com/2018/02/encrypt-decrypt-data-golang-application-crypto-packages/

Executing the program :

1. Run the pbproxy.go file using IDE with necessary program arguments or
2. Run  the following commands :
        -> go mod init hw4/pbproxy
        -> go mod tidy
        -> Run the suitable server/ client commands
