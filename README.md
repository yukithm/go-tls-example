# go-tls-example

TLS example with client certificate.

## Create certificates

Create CA:

```sh
# macOS
/System/Library/OpenSSL/misc/CA.pl -newca

# RedHat families
/etc/pki/tls/misc/CA -newca
```

Create server key and certificate:

```sh
openssl genrsa -out server.key 4096
openssl req -new -key server.key -out client.csr
openssl ca -policy policy_anything -out server.crt -days 3650 -infiles server.csr
```

Create client key and certificate:

```sh
openssl genrsa -out client.key 4096
openssl req -new -key client.key -out client.csr
openssl ca -policy policy_anything -out client.crt -days 3650 -infiles client.csr
```

## Run server and client

Run server:

```sh
go run server/main.go
```

Run client:

```sh
go run client/main.go
```
