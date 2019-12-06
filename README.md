# tunnel

tunnel is a tool you can use to expose a local service to the network. The server runs persistently and can serve many frontend and backend connections. It looks like this:

```
frontend (web browser) <-> server (tunnel-server) <-> backend (tunnel-client)
```

## Usage/Example

Download `tunnel-client` wherever you are running the service you want to expose. Let say your service is running on `localhost:8888`. When you run `tunnel-client localhost:8888` it will print a URL you can click on.

Static precompiled binaries (Linux, Mac, Windows) are avaliable under CI/CD. 

The `-hostname <hostname>` option can be provided to request a specific hostname. However, each hostname is temporarily protected by a secret token. The token doesn't matter when using random URLs, but you should specify `-token <token>` if you want to use the same url multiple times.

## Limitations

`tunnel-client` only works with plain text protocols (HTTP). Whatever you expose will be encrypted during all segements of transfer. You technically could expose any TCP port, but it would require a custom frontend which could interpet tls wrapped traffic.

## Design

TLS Server Name Indication (SNI) is what enables the whole system. Basically when you connect to a TLS server, you indicate which name you are trying to contact in clear text. We can route frontend and backend connections based on what SNI they provide.

When you run `tunnel-client`, it will make a number of preemptive connections to `tunnel-server`. The connections sit idle until a client connects. If the connection is used/disconnected/killed, `tunnel-client` automatically opens additional connections to continually service traffic. Many clients should be able to connect. 