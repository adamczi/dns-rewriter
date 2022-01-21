shitty code yet, but works as a PoC


# dns-rewriter

Tool that substitutes IPv4 addresses in DNS responses. Run it with a chosen IPv4 address and make your applications receive different IP for each of their queries. As this modifies responses not requests, original values remain in DNS servers' logs.

As for now it only supports modification of "A" DNS responses. Also UDP only. Requires support of netfilter queues in the OS (Linux mainly, tested on 5.10.*) and optionally resolvconf.

Requires CAP_NET_ADMIN on Linux, for testing can be quickly granted with simple `sudo`.

This program picks up current DNS servers from `/etc/resolv.conf` file. If this file is nonexistent, have no `nameserver` entries in it or you don't use resolvconf, there is additional flag `-s <IPv4 address>` to explicitly modify traffic coming from this single IP.

## How to:

Step 1) run dns-rewriter. Pass `-t <domain>=<IPv4 address>` that will be included in every DNS response:

    sudo ./dns-rewriter -t example.com=1.2.3.4

Step 2) test with some DNS tool like dig or nslookup:

    nslookup example.com

Step 3) observe modified responses:

    [user@linux ~]$ nslookup example.com
    Server:         192.168.1.1
    Address:        192.168.1.1#53

    Non-authoritative answer:
    Name:   example.com
    Address: 1.2.3.4

To pass more than one domain-IP pair, separate them with colon`,` for example `-t example.com=1.2.3.4,hello.net=2.3.4.5`. Program will clean up `iptables` rules on exit automatically, provided it exits using SIGINT (regular ctrl+c), SIGQUIT or SIGTERM.

### I don't want to modify all responses, just from one DNS server:
This is what `-s` switch is here for. Run

    sudo ./dns-rewriter -t example.com=1.2.3.4 -s 9.9.9.9

and only responses coming from DNS server at 9.9.9.9 will be modified.

## Compile
Try to compile on your OS:

1. `cargo build` in the main dir
2. then just run `./target/debug/dns-rewriter` as superuser (trust me)

## Help page just in case

    dns-rewriter 0.1.0

    USAGE:
        dns-rewriter [FLAGS] [OPTIONS] -t <target-addrs>

    FLAGS:
        -h, --help       Prints help information
        -V, --version    Prints version information
        -v, --verbose    Verbose mode. When not verbose '.' (dot) means non-DNS packet and 'X' means unhandled DNS packet

    OPTIONS:
        -s <source-ipaddr>        (Optional) IPv4 address of the source DNS server
        -t <target-addrs>         Domain and IPv4 pairs separated by colon, e.g. example.com=1.2.3.4,hello.net=2.3.4.5