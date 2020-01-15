use std::{cmp, env, io};
use std::convert::TryFrom;
use std::collections::hash_map::{HashMap, Entry};

use pnet::datalink::{self, NetworkInterface};
use pnet::packet::tcp::TcpFlags;
use tcp_iterator::{TcpIterator, Packet};

use connection_state::Connection;
use types::Flow;
use crate::connection_state::ConnectionOptions;
use crate::event::ConsoleReporter;

mod connection_state;
mod event;
mod tcp_iterator;
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
    let mut connections: HashMap<Flow, Connection> = HashMap::new();

    loop {
        match tcp_packets.next()? {
            Packet::Tcp(packet) => {
//                println!("Got TCP packet \n\
//                         \t ethernet: src={e_src}, dst={e_dst}\n\
//                         \t ipv4: src={i_src}, dst={i_dst}\n\
//                         \t tcp: src={t_src}, dst={t_dst}, syn={syn}, ack_f={ack_f}, ack={ack}, seq={seq}, rst={rst}, fin={fin}",
//                         e_src= packet.ethernet.get_source(), e_dst= packet.ethernet.get_destination(),
//                         i_src= packet.ip.get_source(), i_dst= packet.ip.get_destination(),
//                         t_src= packet.tcp.get_source(), t_dst= packet.tcp.get_destination(),
//                         syn= packet.tcp.get_flags() & TcpFlags::SYN != 0,
//                         ack_f= packet.tcp.get_flags() & TcpFlags::ACK != 0,
//                         ack= packet.tcp.get_acknowledgement(),
//                         seq= packet.tcp.get_sequence(),
//                         rst= packet.tcp.get_flags() & TcpFlags::RST != 0,
//                         fin= packet.tcp.get_flags() & TcpFlags::FIN != 0);
                let flow = cmp::min(Flow::from(&packet), Flow::from(&packet).reverse());
                match connections.entry(flow) {
                    Entry::Occupied(mut connection) => {
                        connection.get_mut().receive_packet(packet);
                    }
                    Entry::Vacant(new_connection) => {
                        println!("New connection: {:?}", flow);
                        let options = ConnectionOptions {
                            attack_reporter: Box::new(ConsoleReporter::default()),
                            skip_hijack_detection_count: 1000,
                        };
                        new_connection.insert(Connection::from_packet(packet, options));
                    }
                }
            }
            _ => {}
        }
    }

}
