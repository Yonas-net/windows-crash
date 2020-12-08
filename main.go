package main

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
)

func main() {
	port := flag.Int("p", 0, "On which port the server starting to listen")
	privKey := flag.String("pk", " ", "Private Key Certificate Chain")
	pubKey := flag.String("puk", " ", "Certificate Chain")
	caKey := flag.String("ck", " ", "CA")
	flag.Parse()

	if *port == 0 {
		log.Fatalln("SERVER: Port must not be empty")
	}

	if *privKey == " "  {
		log.Fatalln("SERVER: Private Key must not be empty")
	}

	if *pubKey == " " {
		log.Fatalln("SERVER: Public Key must not be empty")
	}

	if *caKey == " " {
		log.Fatalln("SERVER: CA must not be empty")
	}

	rootCAs, err := ioutil.ReadFile(*caKey)
	if err != nil {
		log.Fatalf("SERVER: Error while loading CA files %s", err)
	}

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(rootCAs)

	cert, err := tls.LoadX509KeyPair(*pubKey, *privKey)
	if err != nil {
		log.Fatalf("SERVER: Loading certificate keys error: %s\n", err)
	}

	config := tls.Config{
		ClientCAs: caCertPool,
		ClientAuth: tls.RequireAndVerifyClientCert,
		Certificates: []tls.Certificate{cert},
	}
	config.Rand = rand.Reader
	listenOn := fmt.Sprintf("%s%d", "0.0.0.0:", *port)
	listener , err := tls.Listen("tcp", listenOn, &config)
	if err != nil {
		log.Fatalf("SERVER: listen: %s", err)
	}

	log.Printf("%s%d%s", "SERVER: Started listening on '0.0.0.0:", *port, "'")

	for  {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("SERVER: Incoming Connection Error: %s", err)
			break
		}

		log.Printf("SERVER: Accepted connection from %s", conn.RemoteAddr())
		tlsCon, ok := conn.(*tls.Conn)
		if ok {
			log.Print("SERVER: Connection approved from Server")
			state := tlsCon.ConnectionState()
			for _, i := range state.PeerCertificates {
				log.Print(x509.MarshalPKIXPublicKey(i.PublicKey))
			}
		}

		go ProcessIncomingConnection(conn)
	}
}

func ProcessIncomingConnection(conn net.Conn) {
	defer conn.Close()
	buf := make([]byte, 512)
	for {
		log.Print("SERVER: Connection: Waiting for the client")
		n, err := conn.Read(buf)
		if err != nil {
			log.Printf("SERVER: Connection: Starting reading Error: %s", err)
			break
		}
		log.Printf("SERVER: Connection: Received %q\n", string(buf[:n]))
		n, err = conn.Write(buf[:n])

		n, err = conn.Write(buf[:n])
		log.Printf("SERVER: Connection: Sending %d bytes", n)

		if err != nil {
			log.Printf("SERVER: Connection: Sending data to the client Error: %s", err)
			break
		}
	}
	log.Println("SERVER: Connection: Socket closed")
}
