use std::net::Ipv4Addr;
use structopt::StructOpt;
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::ipv4::{Ipv4Packet,MutableIpv4Packet, checksum};
use pnet::packet::udp::{MutableUdpPacket,ipv4_checksum};
use pnet::packet::Packet;
extern crate nfqueue;
extern crate libc;

#[derive(StructOpt, Debug)]
#[structopt()]
struct Opt {
    /// IPv4 address to be set in the DNS response
    #[structopt(short="i")]
    ipv4address: String,

    /// nfqueue ID
    #[structopt(short="q")]
    queue: u16
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

// TODO: TCP handling
// fn handle_tcp_packet(id: u32, source: Ipv4Addr, destination: Ipv4Addr, packet: &[u8]) -> MutableTcpPacket {}

fn handle_udp_packet(id: u32, source: Ipv4Addr, destination: Ipv4Addr, packet: &[u8], new_ipv4_address: [u8; 4]) -> MutableUdpPacket {
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

        // Substitue IP address here:
        let mut new_dns_body = u.payload().to_owned();
        new_dns_body[length_before-1] = new_ipv4_address[3];
        new_dns_body[length_before-2] = new_ipv4_address[2];
        new_dns_body[length_before-3] = new_ipv4_address[1];
        new_dns_body[length_before-4] = new_ipv4_address[0];

        // Prepare new UDP packet and fill header with previous data
        let mut nudp = MutableUdpPacket::owned(new_data).unwrap();
        nudp.set_source(u.get_source());
        nudp.set_destination(u.get_destination());
        nudp.set_length(u.get_length());
        nudp.set_payload(&mut new_dns_body[..]);
        // Can skip checksum by hardcoding static 0x0 value, should work as per RFC 768
        nudp.set_checksum(ipv4_checksum(&nudp.to_immutable(), &source, &destination));

        nudp
    } else {
        println!("[{}]: Malformed UDP Packet", id);
        MutableUdpPacket::new(&mut[]).unwrap()
    }
}


fn handle_transport_protocol(
    id: u32,
    source: Ipv4Addr,
    destination: Ipv4Addr,
    protocol: IpNextHeaderProtocol,
    packet: &[u8],
    new_ipv4_address: [u8; 4]
) -> MutableUdpPacket {
    match protocol {
        IpNextHeaderProtocols::Udp => {
            handle_udp_packet(id, source, destination, packet, new_ipv4_address)
        },
        // IpNextHeaderProtocols::Tcp => handle_tcp_packet(id, source, destination, packet),
        _ => {
            println!(
                "[{}]: Unknown packet: {} > {}; protocol: {:?} length: {}",
                id,
                source,
                destination,
                protocol,
                packet.len()
            );
            return MutableUdpPacket::new(&mut[]).unwrap()
        },
    }
}


fn callback(msg: &nfqueue::Message, custom_data: &mut (State, [u8; 4])) {
    let (state, new_ipv4_address) = custom_data;
    state.count += 1;
    println!(" -> {} msg: {}", msg.get_id(), msg);

    let header = Ipv4Packet::new(msg.get_payload());
    match header {
        Some(h) => {
            let returned = handle_transport_protocol(
                msg.get_id(),
                h.get_source(),
                h.get_destination(),
                h.get_next_level_protocol(),
                h.payload(),
                new_ipv4_address.to_owned()
            );

            // Create empty IPv4 packet and fill it's header part
            let mut ipv4_data = vec![0u8; 20 + returned.packet().len()];
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
            new_ipv4_packet.set_payload(returned.packet());
            // Finally calculate checksum. Same as with UDP, 0x0 should work as well
            new_ipv4_packet.set_checksum(checksum(&new_ipv4_packet.to_immutable()));

            // Accept the packet with new data
            msg.set_verdict_full(nfqueue::Verdict::Accept, 1, &new_ipv4_packet.packet())
        },
        None => {
            println!("Malformed IPv4 packet");
            msg.set_verdict(nfqueue::Verdict::Drop)
        }
    }
}

fn main() {
    let opt = Opt::from_args();
    let new_ipv4_address = validate_ipv4(opt.ipv4address);  
    let mut q = nfqueue::Queue::new((State::new(), new_ipv4_address));
    q.open();
    let rc = q.bind(libc::AF_INET);
    assert!(rc==0);
    q.create_queue(opt.queue, callback);
    q.set_mode(nfqueue::CopyMode::CopyPacket, 0xffffff);
    q.run_loop();
    q.close();
}