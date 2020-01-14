use std::{env, io};
use std::convert::TryFrom;

use pnet::datalink::{self, NetworkInterface};
use pnet::packet::tcp::TcpFlags;
use tcp_iterator::{TcpIterator, Packet};

mod tcp_iterator;
mod connection_state;
mod types;
mod utils;

fn main() -> io::Result<()> {
    let interface_name = env::args().nth(1).expect("interface not given");
    let interface_names_match =
        |iface: &&NetworkInterface| iface.name == interface_name;

    // Find the network interface with the provided name
    let interfaces = datalink::interfaces();
    let interface = interfaces.iter()
        .find(interface_names_match);

    let interface = match interface {
        Some(iface) => iface,
        None => {
            eprintln!("Interface is not found. Here's list of available: {:?}", interfaces);
            return Err(io::ErrorKind::InvalidInput.into())
        }
    };

    let mut tcp_packets = TcpIterator::try_from(interface)?;

    loop {
        match tcp_packets.next()? {
            Packet::Tcp(layers) => {
                let funny_filter = |ip, port| port == 6669;
                if !funny_filter(layers.ip.get_source(), layers.tcp.get_source()) && !funny_filter(layers.ip.get_destination(), layers.tcp.get_destination()) {
                    continue;
                }
                println!("Got TCP packet \n\
                         \t ethernet: src={e_src}, dst={e_dst}\n\
                         \t ipv4: src={i_src}, dst={i_dst}\n\
                         \t tcp: src={t_src}, dst={t_dst}, syn={syn}, ack_f={ack_f}, ack={ack}, seq={seq}, rst={rst}, fin={fin}",
                         e_src=layers.ethernet.get_source(), e_dst=layers.ethernet.get_destination(),
                         i_src=layers.ip.get_source(), i_dst=layers.ip.get_destination(),
                         t_src=layers.tcp.get_source(), t_dst=layers.tcp.get_destination(),
                         syn=layers.tcp.get_flags() & TcpFlags::SYN != 0,
                         ack_f=layers.tcp.get_flags() & TcpFlags::ACK != 0,
                         ack=layers.tcp.get_acknowledgement(),
                         seq=layers.tcp.get_sequence(),
                         rst=layers.tcp.get_flags() & TcpFlags::RST != 0,
                         fin=layers.tcp.get_flags() & TcpFlags::FIN != 0);
            }
            _ => {}
        }
    }

}
