shitty code yet, but works as a PoC


# dns-rewriter

Tool that substitutes IPv4 addresses in DNS responses. Run it with a chosen IPv4 address and make your applications receive different IP for each of their queries. As this modifies responses not requests, original values remain in DNS servers' logs.

As for now it only supports modification of "A" DNS responses into a single IP address. Also UDP only. Requires support of netfilter queues in the OS (Linux mainly, tested on 5.10.*).

Requires CAP_NET_ADMIN on Linux, for testing can be quickly granted with simple `sudo`.

## How to:

Step 1) run dns-rewriter. Pass `-t` (IPv4 address) that will be included in DNS responses and `-s` for the DNS server address that will be answering the query:

    sudo ./dns-rewriter -t 1.2.3.4 -s 9.9.9.9

Step 2) test with some DNS tool like dig or nslookup:

    nslookup example.com @9.9.9.9

Step 3) observe modified responses:

    [user@linux ~]$ nslookup example.com 9.9.9.9
    Server:         9.9.9.9
    Address:        9.9.9.9#53

    Non-authoritative answer:
    Name:   example.com
    Address: 1.2.3.4

Program will clean up `iptables` rules on exit automatically, provided it exits because of SIGINT (regular ctrl+c), SIGQUIT or SIGTERM.

## Compile
Try to compile on your OS:

1. `cargo build` in the main dir
2. then just run `./target/debug/dns-rewriter` as superuser (trust me)