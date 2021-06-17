shitty code yet, but works as a PoC


# dns-rewriter

Tool that substitutes IPv4 addresses in DNS responses. Run it with chosen IPv4 address and make your applications receive different this for each of their queries. As this modifies responses not requests, original values remain in DNS servers' logs.

As for now it only supports modification of "A" DNS responses into a single IP address. Also UDP only. Requires support of netfilter queues in the OS (Linux mainly, tested on 5.10.*).

Requires CAP_NET_ADMIN on Linux, for testing can be quickly granted with simple `sudo`.

## How to:

Step 1) create new nfqueue on INPUT traffic. Choose `--source` address (DNS server address), choose arbitrary queue ID (`--queue-num`):

    sudo iptables -A INPUT --source 9.9.9.9 -j NFQUEUE --queue-num 5

Step 2) run dns-rewriter. Pass `-i` (IPv4 address) that will be included in DNS responses and previous `-q`ueue number:

    sudo dns-rewriter -i 1.2.3.4 -q 5

Step 3) test with some DNS tool like dig or nslookup:

    nslookup example.com @9.9.9.9


Step 4) observe modified responses:

    [user@linux ~]$ nslookup example.com 9.9.9.9
    Server:         9.9.9.9
    Address:        9.9.9.9#53

    Non-authoritative answer:
    Name:   example.com
    Address: 1.2.3.4


## Compile
Try to compile on your OS:

1. `cargo build` in the main dir
2. then just run `./target/debug/dns-rewriter` as superuser (trust me)