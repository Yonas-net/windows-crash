package main

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/Yonas-net/windows-crash/lib/base"
	"io/ioutil"
	"log"
	math "math/rand"
	"net"
)

type Decoder struct {
	JSONRPC string
	Method  string
	Params  interface{}
}

type Encoder struct {
	JSONRPC string  `json:"jsonrpc"`
	Method  string  `json:"method"`
	Params  Updates `json:"params"`
}

type Updates struct {
	Update    map[string]ConfigInfo `json:"update"`
	Update_v2 map[string]ConfigInfo `json:"update_v2"`
	Checksums map[string]ConfigInfo `json:"checksums"`
}

type ConfigInfo map[string]string

func main() {
	port := flag.Int("p", 0, "On which port the server starting to listen")
	privKey := flag.String("pk", " ", "Private Key Certificate Chain")
	pubKey := flag.String("crt", " ", "Certificate Chain")
	caKey := flag.String("ca", " ", "CA")
	zoneDir := flag.String("z", " ", "Zone name you want to sync to")
	files   := flag.Int("f", 0, "Amount of files to be synced to the specified zone")

	flag.Parse()

	if *port == 0 {
		log.Fatalln("SERVER: Port must not be empty")
	}

	if *files == 0 {
		log.Fatalln("SERVER: Amount of config files must not be empty")
	}

	IsEmpty(privKey, "pk")
	IsEmpty(pubKey, "crt")
	IsEmpty(caKey, "ca")
	IsEmpty(zoneDir, "z")

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
	listener, er := tls.Listen("tcp", listenOn, &config)

	if er != nil {
		log.Fatalf("SERVER: Error while server starting to listen: %s", err)
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

		go ProcessIncomingConnection(conn, files, zoneDir)
	}
}

func ProcessIncomingConnection(conn net.Conn, files *int, zone *string) {
	defer conn.Close()

	for {
		log.Print("SERVER: Connection: Waiting for the client")

		mes, err := base.ReadNetStringFromStream(conn, 1024 * 1024)

		if err != nil {
			log.Printf("SERVER: Connection: Starting reading Error: %s", err)
			break
		}

		var decoder Decoder
		err = json.Unmarshal(mes, &decoder)

		if err != nil {
			log.Fatalf("SERVER: Connection: Error while decoding JSRPC message. %s", err)
		}

		if decoder.Method == "icinga::Hello" {
			log.Printf("SERVER: JsonRpcConnection: Received %q from the client\n", decoder.Method)
		}

		encoder := &Encoder{
			JSONRPC: "2.0",
			Method: "config::Update",
			Params: Updates{
				Update: map[string]ConfigInfo{
					*zone: {},
				},
				Update_v2: map[string]ConfigInfo{
					*zone: {},
				},
				Checksums: map[string]ConfigInfo{
					*zone: {},
				},
			},
		}

		r := math.Intn(*files)
		for i := 0; i < r; i++ {
			file := GenerateFile("conf")

			encoder.Params.Update[*zone][file] = " "
			encoder.Params.Update_v2[*zone][file] = " "
			encoder.Params.Checksums[*zone][file] = " "
		}

		mess, err := json.Marshal(&encoder)

		if err != nil{
			log.Printf("SERVER: JsonRpcConnection: Error while encoding JSRPC message. %s", err)
			continue
		}

		log.Printf("SERVER: JsonRpcConnection: Sending config::Update JSRPC message: %s", mess)

		err = base.WriteNetStringToStream(conn, mess)

		if err != nil {
			log.Printf("SERVER: JsonRpcConnection: Error while sending json encoded JSRPC message: %s", err)
			continue
		}
	}

	log.Println("SERVER: Connection: Socket closed")
}

func IsEmpty(val *string, desc string)  {
	if *val == " " {
		log.Fatalf("SERVER: Required command line '%s' argment is empty\n", desc)
	}
}

func GenerateFile(suffix string) string {
	r := math.Intn(1000000)
	fname := fmt.Sprintf("%d.%s", r, suffix)

	return fname
}
