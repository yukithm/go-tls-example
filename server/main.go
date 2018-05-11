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
	"net"
)

var (
	certFile   = "./server.crt"
	keyFile    = "./server.key"
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

	log.Printf("Server started on %s", addr)
	if err := serve("tcp", addr); err != nil {
		panic(err)
	}
}

func serve(network, addr string) error {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return err
	}

	var clientCertPool *x509.CertPool
	if caCertFile != "" {
		caCertPem, err := ioutil.ReadFile(caCertFile)
		if err != nil {
			return fmt.Errorf("Unable to read CA cert: %s", err)
		}

		clientCertPool = x509.NewCertPool()
		if ok := clientCertPool.AppendCertsFromPEM(caCertPem); !ok {
			return errors.New("Failed to append CA cert to the pool")
		}
	}

	tlsConfig := &tls.Config{
		Certificates:     []tls.Certificate{cert},
		ClientAuth:       tls.RequireAndVerifyClientCert,
		ClientCAs:        clientCertPool,
		CurvePreferences: []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		},
		PreferServerCipherSuites: true,
		MinVersion:               tls.VersionTLS12,
	}
	tlsConfig.BuildNameToCertificate()

	lis, err := tls.Listen(network, addr, tlsConfig)
	if err != nil {
		return err
	}
	defer lis.Close()

	for {
		conn, err := lis.Accept()
		if err != nil {
			return err
		}

		go handleClient(conn)
	}
}

func handleClient(conn net.Conn) {
	defer conn.Close()

	log.Printf("Accept client from %s", conn.RemoteAddr())
	if tconn, ok := conn.(*tls.Conn); ok {
		if err := tconn.Handshake(); err != nil {
			log.Println(err)
			return
		}
		state := tconn.ConnectionState()
		for _, v := range state.PeerCertificates {
			fmt.Println(x509.MarshalPKIXPublicKey(v.PublicKey))
			fmt.Println(v.Subject)
		}
	}

	_, err := io.Copy(conn, conn)
	if err != nil {
		log.Println(err)
	}

	log.Println("Close client")
}
