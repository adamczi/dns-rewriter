use std::io;
use std::io::Write;
use std::net::Ipv4Addr;
use std::collections::HashMap;
use std::io::Error;
use std::thread;
use structopt::StructOpt;
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::ipv4::{Ipv4Packet,MutableIpv4Packet, checksum};
use pnet::packet::udp::{MutableUdpPacket,ipv4_checksum};
use pnet::packet::Packet;
extern crate nfqueue;
extern crate libc;
extern crate iptables;
extern crate signal_hook;

#[derive(StructOpt, Debug)]
#[structopt()]
struct Opt {
    /// IPv4 address to be set in the DNS response
    #[structopt(short="t")]
    target_ipaddr: String,

    // IPv4 address of the source DNS server
    #[structopt(short="s")]
    source_ipaddr: String,

    // Verbose mode
    #[structopt(short="v")]
    verbose: bool
}

struct State {
    count: u32,
}

impl State {
    // Count flowing packets amount
    pub fn new() -> State {
        State { count: 0 }
    }
}

const QUERIES_START: usize = 12;
       
const QTYPES_MAP: [(i32, &str); 47] = [
    (1, "A"),
    (2, "NS"),
    (5, "CNAME"),
    (6, "SOA"),
    (12, "PTR"),
    (13, "HINFO"),
    (15, "MX"),
    (16, "TXT"),
    (17, "RP"),
    (18, "AFSDB"),
    (24, "SIG"),
    (25, "KEY"),
    (28, "AAAA"),
    (29, "LOC"),
    (33, "SRV"),
    (35, "NAPTR"),
    (36, "KX"),
    (37, "CERT"),
    (39, "DNAME"),
    (42, "APL"),
    (43, "DS"),
    (44, "SSHFP"),
    (45, "IPSECKEY"),
    (46, "RRSIG"),
    (47, "NSEC"),
    (48, "DNSKEY"),
    (49, "DHCID"),
    (50, "NSEC3"),
    (51, "NSEC3PARAM"),
    (52, "TLSA"),
    (53, "SMIMEA"),
    (55, "HIP"),
    (59, "CDS"),
    (60, "CDNSKEY"),
    (61, "OPENPGPKEY"),
    (62, "CSYNC"),
    (63, "ZONEMD"),
    (64, "SVCB"),
    (65, "HTTPS"),
    (108, "EUI48"),
    (109, "EUI64"),
    (249, "TKEY"),
    (250, "TSIG"),
    (256, "URI"),
    (257, "CAA"),
    (32768, "TA"),
    (32769, "DLV")
];

fn validate_ipv4(ipv4address: String) -> [u8; 4] {
    // Validate passed arg against IPv4. Returns array with 4 octets or terminates program
    let ipv4 = ipv4address.parse::<Ipv4Addr>();
    match ipv4 {
        Ok(ipv4) => {
            ipv4.octets()
        }
        Err(e) => {
            println!("Error: {}", e);
            std::process::exit(1)
        }
    }

}

fn guess_if_dns(udp_data: &[u8], udp_port: u16) -> bool {
    // There are no ways to tell for sure that a packet is DNS, therefore 
    // we will validate parts of the packet that we expect to hold certain
    // values. This is also why array indexes are hardcoded here.
    // First 8 bytes are (2 bytes each):
    // - Source Port
    // - Destination Port
    // - Length
    // - Checksum
    // Then comes the payload processed here. Values stored in "udp_data" are `u8` integers.

    // Check if "Response" QR bit of DNS packet is set (1st bit)
    if (udp_data[2] ^ 128) > 128 {
        return false
    }

    // Next 4 bits should be 0000 (OPCODE: standard query)
    if (udp_data[2] ^ 135) > 135 {
        return false
    }

    // Don't support non-standard DNS ports
    if udp_port != 53 {
        return false
    }

    // Does it have at least 1 answer?
    // What about unresolved domains?
    // if udp_data[6]+udp_data[7] == 0 {
    //     return false
    // }

    // All checks passed, we hope it's DNS
    true
}

fn print_domain(domain: &[u8]) {
    let mut s: String = String::from("");
    for c in domain {
        s.push(*c as char);
    }
    println!("{}",s);
}

fn get_query_type(_first_byte: Option<&u8>, second_byte: Option<&u8>, qtypes: &HashMap<i32, &str>) -> (bool, String) {
    // Extract DNS query/response type from the static list. `first_byte` remains here as 'todo' in case
    // that TA/DLV types would be required to be handled.
    //
    // TODO: Returns `true` if type is A, `false` otherwise, as other types require individual processing.
    match second_byte {
        Some(&a) => {
            let ai32 = a as i32;
            match qtypes.get(&ai32) {
                Some(b) => {
                    if ai32 == 1 {
                        let msg = format!("Type: {}", b);
                        (true, msg)
                    }
                    else {
                        let msg = format!("Type: {} - not implemented", b);
                        (false, msg)
                    }
                },
                None => {
                    let msg = format!("Unknown type: {}",a);
                    (false, msg)
                }
            }
        },
        None => (false, "Query Type byte is null".to_string())
    }
}

fn print_packet(
    queried_domain: &[u8],
    req_qt_msg: &str,
    resp_qt_msg: &str,
    payload: &[u8],
    new_ipv4_addr: &[u8; 4],
    itersize: &(usize, Option<usize>)
) {
    if Opt::from_args().verbose {
        println!("------\nRequest");
        print_domain(queried_domain);
        println!("{}", req_qt_msg);
        println!("\nResponse");
        println!("{}", resp_qt_msg);

    };
    println!("{}.{}.{}.{} -> {}.{}.{}.{}",
        payload[payload.len()-itersize.0],
        payload[payload.len()-itersize.0+1],
        payload[payload.len()-itersize.0+2],
        payload[payload.len()-itersize.0+3],
        new_ipv4_addr[0],
        new_ipv4_addr[1],
        new_ipv4_addr[2],
        new_ipv4_addr[3]
    );
}

fn substitute_addr(payload: std::vec::Vec<u8>, new_ipv4_addr: [u8; 4], qtypes: HashMap<i32, &str>) -> Option<std::vec::Vec<u8>> {
    // Resolved IP address position in payload depends on for example the length
    // of the domain queried. We will have to calculate this position first, then
    // substitute the address.

    // let questions_no = payload[4]+payload[5];
    // let answers_no = payload[6]+payload[7];
    let mut payload_iter = payload.iter().skip(QUERIES_START);

    // Query part
    let mut queried_domain: Vec<u8> = Vec::new();
    let mut queried_domain_len: usize = 1; // dummy value >0
    while queried_domain_len != 0 {
        // Extract queried domain name
        if let Some(&v) = payload_iter.next() {
            queried_domain_len = usize::from(v);
        }
        else {}

        for _ in 0..queried_domain_len {
            if let Some(&c) = payload_iter.next() {
                queried_domain.push(c);
            }
            else {}
        }
        if queried_domain_len > 0 { queried_domain.push(46); } // a dot
    }
    let request_qt: (bool, String) = get_query_type(payload_iter.next(), payload_iter.next(), &qtypes);
    payload_iter.next(); // Skip query Class (2 bytes)
    payload_iter.next();

    // Response part
    payload_iter.next(); // Skip response Name pointer (2 bytes)
    payload_iter.next();
    let response_qt: (bool, String) = get_query_type(payload_iter.next(), payload_iter.next(), &qtypes);
    if !response_qt.0 {
        // Unsupported query/response type
        return None
    }
    payload_iter.next(); // Skip response Class (2 bytes)
    payload_iter.next();
    payload_iter.next(); // Skip response TTL (4 bytes)
    payload_iter.next();
    payload_iter.next();
    payload_iter.next();
    payload_iter.next(); // Skip data length (2 bytes)
    payload_iter.next();
    
    // Find out current index and substitute IP address
    let itersize = payload_iter.size_hint();
    let mut new_dns_body = payload.to_owned();
    new_dns_body[payload.len()-itersize.0] = new_ipv4_addr[0];
    new_dns_body[payload.len()-itersize.0+1] = new_ipv4_addr[1];
    new_dns_body[payload.len()-itersize.0+2] = new_ipv4_addr[2];
    new_dns_body[payload.len()-itersize.0+3] = new_ipv4_addr[3];

    print_packet(
        &queried_domain,
        &request_qt.1,
        &response_qt.1,
        &payload,
        &new_ipv4_addr,
        &itersize
    );
    
    Some(new_dns_body)
}

// TODO: TCP handling
// fn handle_tcp_packet(id: u32, source: Ipv4Addr, destination: Ipv4Addr, packet: &[u8]) -> MutableTcpPacket {}

fn handle_udp_packet<'a>(id: u32, source: Ipv4Addr, destination: Ipv4Addr, packet: &'a[u8], new_ipv4_address: [u8; 4], qtypes: HashMap<i32, &str>) -> Option<MutableUdpPacket<'a>> {
    let mut s_packet_data = packet.to_owned();
    let ms_packet_data = s_packet_data.as_mut_slice();
    let udp = MutableUdpPacket::new(ms_packet_data);
    
    if let Some(u) = udp {
        // TODO: CNAME handling
        let length_before = u.payload().len();

        // We only change single IP address which has a fixed 4-byte
        // length, so overall packet size stays the same, which is
        // 8 bytes for UDP header + the length of original payload
        let new_data = vec![0u8; 8 + length_before];

        // Is it DNS?
        if !guess_if_dns(&u.payload(), u.get_source()) {
            println!("[{}]: I guess it's not a DNS packet", id);
            return MutableUdpPacket::new(&mut [])
        };

        // Do actual substitutions here and obtain new body to return
        match substitute_addr(u.payload().to_owned(), new_ipv4_address, qtypes) {
            Some(new_dns_body) => {
                // Prepare new UDP packet and fill header with previous data
                let mut nudp = MutableUdpPacket::owned(new_data).unwrap();
                nudp.set_source(u.get_source());
                nudp.set_destination(u.get_destination());
                nudp.set_length(u.get_length());
                nudp.set_payload(&new_dns_body[..]);
                // Possible to skip below by hardcoding static 0x0 value, should work as per RFC 768
                nudp.set_checksum(ipv4_checksum(&nudp.to_immutable(), &source, &destination));
        
                Some(nudp)
            },
            // Return empty data if Response Type not implemented
            None => MutableUdpPacket::new(&mut[])
        }

    } else {
        println!("[{}]: Malformed UDP Packet", id);
        MutableUdpPacket::new(&mut[])
    }
}


fn handle_transport_protocol<'a>(
    id: u32,
    source: Ipv4Addr,
    destination: Ipv4Addr,
    protocol: IpNextHeaderProtocol,
    packet: &'a[u8],
    new_ipv4_address: [u8; 4],
    qtypes: HashMap<i32, &str>
) -> Option<MutableUdpPacket<'a>> {
    match protocol {
        IpNextHeaderProtocols::Udp => {
            handle_udp_packet(id, source, destination, packet, new_ipv4_address, qtypes)
        },
        // IpNextHeaderProtocols::Tcp => handle_tcp_packet(id, source, destination, packet),
        _ => {
            if Opt::from_args().verbose {
                println!(
                    "[{}]: Unknown packet: {} > {}; protocol: {:?} length: {}",
                    id,
                    source,
                    destination,
                    protocol,
                    packet.len()
                );
            }
            else {
                print!(".");
                io::stdout().flush().unwrap();
            }
            MutableUdpPacket::new(&mut[])
        },
    }
}


fn callback(msg: &nfqueue::Message, custom_data: &mut (State, [u8; 4], HashMap<i32, &str>)) {
    let (state, new_ipv4_address, qtypes) = custom_data;
    state.count += 1;
    // println!(" -> {} msg: {}", msg.get_id(), msg);

    let header = Ipv4Packet::new(msg.get_payload());
    match header {
        Some(h) => {
            let returned = handle_transport_protocol(
                msg.get_id(),
                h.get_source(),
                h.get_destination(),
                h.get_next_level_protocol(),
                h.payload(),
                new_ipv4_address.to_owned(),
                qtypes.to_owned()
            );

            match returned {
                Some(packet) => {
                    // Create empty IPv4 packet and fill it's header part
                    let mut ipv4_data = vec![0u8; 20 + packet.packet().len()];
                    let mut new_ipv4_packet = MutableIpv4Packet::new(&mut ipv4_data).unwrap();
                    new_ipv4_packet.set_version(h.get_version());
                    new_ipv4_packet.set_total_length(h.get_total_length()); //
                    new_ipv4_packet.set_header_length(h.get_header_length());
                    new_ipv4_packet.set_dscp(h.get_dscp());
                    new_ipv4_packet.set_ecn(h.get_ecn());
                    new_ipv4_packet.set_identification(h.get_identification());
                    new_ipv4_packet.set_flags(h.get_flags());
                    new_ipv4_packet.set_fragment_offset(h.get_fragment_offset());
                    new_ipv4_packet.set_ttl(h.get_ttl());
                    new_ipv4_packet.set_source(h.get_source());
                    new_ipv4_packet.set_destination(h.get_destination());
                    new_ipv4_packet.set_next_level_protocol(h.get_next_level_protocol());
                    // Set actual UDP payload
                    new_ipv4_packet.set_payload(packet.packet());
                    // Finally calculate checksum. Same as with UDP, 0x0 should work as well
                    new_ipv4_packet.set_checksum(checksum(&new_ipv4_packet.to_immutable()));

                    // Accept the packet with new data
                    msg.set_verdict_full(nfqueue::Verdict::Accept, 1, &new_ipv4_packet.packet())
                },
                None => {
                    msg.set_verdict(nfqueue::Verdict::Accept)
                }
            }
        },
        None => {
            println!("Malformed IPv4 packet, dropping");
            msg.set_verdict(nfqueue::Verdict::Drop)
        }
    }
}

fn set_queue(ipt: &iptables::IPTables, addr: &[u8; 4]) -> Option<u16> {
    // Creates a new queue. ID of the queue (the `--queue-num` parameter in
    // iptables) is the first one that is free, up to possible 65535 (16 bits)
    let mut options;
    for i in 1..65535_u16 {
        options = format!("--source {}.{}.{}.{} -j NFQUEUE --queue-num {}", addr[0],addr[1],addr[2],addr[3], i);
        if !ipt.exists("filter", "INPUT", options.as_str()).unwrap() {
            ipt.append("filter", "INPUT", options.as_str()).unwrap();
            return Some(i)
        }
    }
    None
}

fn cleanup_queue(addr: &[u8; 4], queue_num: u16) {
    let ipt = iptables::new(false).unwrap();
    let options = format!("--source {}.{}.{}.{} -j NFQUEUE --queue-num {}", addr[0],addr[1],addr[2],addr[3], queue_num);
    println!("Cleaning up {}", options);
    if ipt.exists("filter", "INPUT", options.as_str()).unwrap() {
        ipt.delete("filter", "INPUT", options.as_str()).unwrap();
    }
    else {
        println!("nfqueue: INPUT filter not found, clean it up yourself: \"iptables -D INPUT {}\"", options);
    }
}

fn register_signals(addr: [u8; 4], queue_num: u16) -> Result<(), Error> {
    // Listen for signals, then clean up iptables rule on exit
    let mut signals = signal_hook::iterator::Signals::new(&[
        signal_hook::consts::SIGINT, // ctrl+c
        signal_hook::consts::SIGQUIT,
        signal_hook::consts::SIGTERM
        ])?;
    
    thread::spawn(move || {
        for sig in signals.forever() {
            println!("Received signal {:?}", sig);
            match sig {
                2 | 3 | 15 => {
                    // SIGINT, SIGQUIT, SIGTERM
                    cleanup_queue(&addr.to_owned(), queue_num);
                    std::process::exit(0)
                },
                _ => {
                    println!("Doing nothing");
                }
            }
        }
    });

    Ok(())
}

fn main() {
    let opt = Opt::from_args();
    let target_ipv4_address = validate_ipv4(opt.target_ipaddr);
    let source_ipv4_address = validate_ipv4(opt.source_ipaddr);
    let ipt = iptables::new(false).unwrap();
    let queue_num = set_queue(&ipt, &source_ipv4_address);
    
    match queue_num {
        Some(queue_num) => {
            match register_signals(source_ipv4_address, queue_num) {
                Ok(()) => {
                    let qtypes: HashMap<i32, &str> = QTYPES_MAP.iter().cloned().collect();
                    let mut q = nfqueue::Queue::new((State::new(), target_ipv4_address.to_owned(), qtypes));
                    q.open();
                    let rc = q.bind(libc::AF_INET);
                    assert!(rc==0);
                    q.create_queue(queue_num, callback);
                    q.set_mode(nfqueue::CopyMode::CopyPacket, 0xffffff);
                    q.run_loop();
                    q.close();
                },
                _ => {
                    println!("Error registering signals");
                    std::process::exit(1)                    
                }
            }
        },
        None => {
            println!("Couldn't create new netfilter queue");
            std::process::exit(1)
        }
    }
}