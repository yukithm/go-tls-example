package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
)

var (
	certFile   = "./client.crt"
	keyFile    = "./client.key"
	caCertFile = "./demoCA/cacert.pem"
)

func init() {
	flag.StringVar(&certFile, "cert", certFile, "certificate file (PEM)")
	flag.StringVar(&keyFile, "key", keyFile, "private key file (PEM)")
	flag.StringVar(&caCertFile, "cacert", caCertFile, "CA certificate file (PEM)")
}

func main() {
	flag.Parse()

	addr := ":8888"
	if flag.NArg() > 0 {
		addr = flag.Arg(0)
	}

	if err := connect("tcp", addr); err != nil {
		panic(err)
	}
}

func connect(network, addr string) error {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return err
	}

	caCertPem, err := ioutil.ReadFile(caCertFile)
	if err != nil {
		return fmt.Errorf("Unable to read CA cert: %s", err)
	}

	caCertPool := x509.NewCertPool()
	if ok := caCertPool.AppendCertsFromPEM(caCertPem); !ok {
		return errors.New("Failed to append CA cert to the pool")
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caCertPool,
		// ServerName:   "localhost",
		InsecureSkipVerify: true,
	}
	tlsConfig.BuildNameToCertificate()

	conn, err := tls.Dial("tcp", addr, tlsConfig)
	if err != nil {
		return err
	}
	defer conn.Close()

	log.Println("Connected to:", conn.RemoteAddr())

	state := conn.ConnectionState()
	for _, v := range state.PeerCertificates {
		fmt.Println(x509.MarshalPKIXPublicKey(v.PublicKey))
		fmt.Println(v.Subject)
	}
	log.Println("Handshake:", state.HandshakeComplete)
	log.Println("Mutual:", state.NegotiatedProtocolIsMutual)

	go io.Copy(conn, os.Stdin)
	io.Copy(os.Stdout, conn)

	return nil
}
