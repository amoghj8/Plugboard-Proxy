package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"flag"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"time"

	"golang.org/x/crypto/pbkdf2"
)

var (
	pFlag      *string
	lFlag      *string
	dstHost    = ""
	dstPort    = ""
	address    = ""
	passphrase = ""
)

// Channel to store bytes written
type Channel struct {
	bytes uint64
}

func main() {

	// Logging the operations in info.log file
	file, err := os.OpenFile("info.log", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	log.SetOutput(file)

	// Parsing command line args
	pFlag = flag.String("p", "", "File containing the ASCII text keyphrase ")
	lFlag = flag.String("l", "", "Specify the listening port which serves as reverse proxy")

	flag.Parse()

	if len(flag.Args()) != 2 {
		panic("must provide destination and port in the format : go run pbproxy.go [-l port] -p <passphrase file> <destination> <port>")
	}

	if *pFlag != "" {
		// Reading the passphrase
		pwdBytes, err := ioutil.ReadFile(*pFlag)
		if err != nil {
			panic(err)
		} else {
			if len(pwdBytes) == 0 {
				panic("passphrase file must contain a passphrase and not be empty")
			}
			passphrase = string(pwdBytes)
		}
	} else {
		panic("password file containing the passphrase must be passed")
	}

	// Get destination host and port
	dstHost = flag.Arg(0)
	dstPort = flag.Arg(1)

	// Storing the destination address
	address = dstHost + ":" + dstPort

	/*
		If listen flag is enabled then run as server accepting client connections
		Else act as client and connect to mentioned address
	*/
	if *lFlag != "" {
		runServer()
	} else {
		runClient()
	}
}

func runServer() {

	// Get the proxy server port
	port := *lFlag

	// Listen to incoming client connections in proxy server port
	listener, err := net.Listen("tcp", ":"+port)
	if err != nil {
		panic(err)
	}

	log.Printf("Proxy server is listening for connections on %s", listener.Addr().String())

	for {
		// Accepting incoming client connections
		conn, err := listener.Accept()
		if err != nil {
			log.Fatalf("error accepting connection from client: %s\n", err)
		} else {
			// Connecting to service and handling the particular connection
			connLocalHost, errLocalHost := net.Dial("tcp", address)
			if errLocalHost != nil {
				log.Println(errLocalHost)
				continue
			}
			go handleDataServerLocalHost(conn, connLocalHost)
		}
	}
}

// Running as client and connecting to mentioned address
func runClient() {
	con, err := net.Dial("tcp", address)
	if err != nil {
		log.Fatalln(err)
	}
	log.Println("Connected to ", address)
	con.SetDeadline(time.Now().Add(time.Second * 60))
	defer func() {
		con.Close()
	}()
	handleDataClient(con)
}

func handleDataClient(con net.Conn) {
	log.Println("Inside handle client function")
	channelDataStructure := make(chan Channel)

	copy := func(readCloser io.ReadCloser, writeCloser io.WriteCloser) {
		defer func() {
			readCloser.Close()
			writeCloser.Close()
		}()

		if readCloser == os.Stdin {
			log.Println("Inside os.Stdin reader closer")
			var written uint64 = 0
			bytes := make([]byte, 64*4096)
			for {
				read, err := readCloser.Read(bytes)
				if err != nil {
					if err, ok := err.(net.Error); ok && err.Timeout() {
						con.Close()
						log.Fatalln("connection closed")
					}
				}
				if read != 0 {
					data := bytes[:read]
					encryptedData := encrypt(string(data))
					write, err := writeCloser.Write(encryptedData)
					con.SetWriteDeadline(time.Now().Add(time.Second * 300))
					if err != nil {
						log.Printf("Found error %s in connection %s\n", err, con.RemoteAddr())
					}
					written += uint64(write)
				}
			}
			channelDataStructure <- Channel{bytes: written}
		} else {
			log.Println("Inside client conn reader closer")
			var written uint64 = 0
			bytes := make([]byte, 64*4096)
			for {
				read, err := readCloser.Read(bytes)
				if err != nil {
					if err, ok := err.(net.Error); ok && err.Timeout() {
						con.Close()
						log.Fatalln("connection closed")
					}
				}
				if read != 0 {
					data := bytes[:read]
					con.SetReadDeadline(time.Now().Add(time.Second * 300))
					decryptedData := decrypt(string(data))
					write, err := writeCloser.Write(decryptedData)
					if err != nil {
						log.Printf("Found error %s in connection %s\n", err, con.RemoteAddr())
					}
					written += uint64(write)
				}
			}
			channelDataStructure <- Channel{bytes: written}
		}

	}

	go copy(con, os.Stdout)
	go copy(os.Stdin, con)

	channel := <-channelDataStructure
	log.Println("Data received (bytes ) : ", channel.bytes)
	channel = <-channelDataStructure
	log.Println("Data sent (bytes) : ", channel.bytes)
}

func handleDataServerLocalHost(conn net.Conn, connLocalHost net.Conn) {
	log.Println("Inside handle server function")
	channelDataStructure := make(chan Channel)

	copy := func(readCloser io.ReadCloser, writeCloser io.WriteCloser) {
		defer func() {
			readCloser.Close()
			writeCloser.Close()
		}()
		if readCloser == connLocalHost {
			log.Println("Inside connLocalHost reader closer")
			var written uint64 = 0
			bytes := make([]byte, 64*4096)
			for {
				read, err := readCloser.Read(bytes)
				if err != nil {
					if err, ok := err.(net.Error); ok && err.Timeout() {
						conn.Close()
					}
				}
				if read != 0 {
					data := bytes[:read]
					encryptedData := encrypt(string(data))
					write, err := writeCloser.Write(encryptedData)
					if err != nil {
						log.Printf("Found error %s in connection %s\n", err, conn.RemoteAddr())
					}
					written += uint64(write)
				}
			}
			channelDataStructure <- Channel{bytes: written}
		} else {
			var written uint64 = 0
			bytes := make([]byte, 64*4096)
			for {
				log.Println("Inside server conn reader closer")
				read, err := readCloser.Read(bytes)
				if err != nil {
					if err, ok := err.(net.Error); ok && err.Timeout() {
						conn.Close()
					}
				}
				if read != 0 {
					data := bytes[:read]
					decryptedData := decrypt(string(data))
					write, err := writeCloser.Write(decryptedData)
					if err != nil {
						log.Printf("Found error %s in connection %s\n", err, conn.RemoteAddr())
					}
					written += uint64(write)
				}
			}
			channelDataStructure <- Channel{bytes: written}
		}
	}

	go copy(conn, connLocalHost)
	go copy(connLocalHost, conn)

	channel := <-channelDataStructure
	log.Println("Data received (bytes) : ", channel.bytes)
	channel = <-channelDataStructure
	log.Println("Data sent (bytes) : ", channel.bytes)
}

// Encrypting the data
func encrypt(content string) []byte {
	// Generating key
	keyBytes := make([]byte, 32)
	if _, err := rand.Read(keyBytes); err != nil {
		panic(err.Error())
	}
	key := pbkdf2.Key([]byte(passphrase), keyBytes, 4096, sha256.Size, sha256.New)
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Fatalln(err.Error())
	}
	// Generating nonce
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Fatalln(err.Error())
	}
	// Encrypting the data
	ciphertext := aesgcm.Seal(append(nonce, key...), nonce, []byte(content), nil)
	log.Println("Encrypted data sent : ", string(ciphertext))
	return ciphertext
}

// Decrypting the data
func decrypt(encryptedData string) []byte {
	log.Println("Encrypted data received : ", encryptedData)
	// Splitting the nonce, key and ciphertext
	nonce, key, ciphertext := encryptedData[:12], []byte(encryptedData[12:44]), encryptedData[44:]
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Fatalln(err.Error())
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Fatalln(err.Error())
	}
	plaintext, err := gcm.Open(nil, []byte(nonce), []byte(ciphertext), nil)
	if err != nil {
		log.Fatalln(err.Error())
	}
	return plaintext
}
