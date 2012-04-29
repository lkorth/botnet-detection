package botnets;

import java.net.InetAddress;
import java.util.ArrayList;

import jpcap.PacketReceiver;
import jpcap.packet.Packet;
import jpcap.packet.TCPPacket;
import jpcap.packet.UDPPacket;

class PacketHandler implements PacketReceiver {
	
	private String localNetwork;
	private ArrayList<Host> hosts;
	
	PacketHandler(String localNetwork){
		this.localNetwork = localNetwork;
	}
	
	//this method is called every time Jpcap captures a packet
	public void receivePacket(Packet packet) {	
		//compare non local network with blacklist and note matches
		if(packet.header[23] == 17) { //udp packets (IP Packet protocol 17)
			UDPPacket p = (UDPPacket) packet;
			if(p.dst_port == 53) { //dns outbound queries only
				System.out.println(convert(p.data)); //print data of dns query
			}
		}
		else if(packet.header[23] == 6) { //tcp packets (IP Packet protocol 6
			TCPPacket p = (TCPPacket) packet;
			storeWorkWeight(p);
		}
	}
	
	//Conversation from byte[] to string. Adapted from http://www.highonphp.com/decoding-udp-dns-requests and http://stackoverflow.com/questions/2201930/convert-ascii-byte-to-string
	private String convert(byte[] data) {
	    StringBuilder sb = new StringBuilder(data.length);
	    for (int i = 13; i < data.length-5; ++ i) {
	        if (data[i] < 0) throw new IllegalArgumentException();
	        else if (data[i] < 32) sb.append('.');
	        else if (data[i] > 32 && data[i] < 127) sb.append((char) data[i]);
	    }
	    return sb.toString();
	}
	
	private boolean isLocalNetwork(InetAddress ip) {
		return ip.getHostAddress().startsWith(localNetwork);
	}
	
	private void storeWorkWeight(TCPPacket packet) { //Described in paper here: http://web.cecs.pdx.edu/~jrb/jrb.papers/sruti06/sruti06.pdf
		if(isLocalNetwork(packet.src_ip)) {
			Host current = new Host(packet.src_ip.getHostAddress());
			int index = hosts.indexOf(current);
			if(index != -1) {
				if(packet.ack)
					hosts.get(index).addAck();
				if(packet.fin)
					hosts.get(index).addFin();
				if(packet.rst)
					hosts.get(index).addRst();
				if(packet.syn)
					hosts.get(index).addSyn();
				hosts.get(index).addToTotal();
			}
			else {
				current.setAck((packet.ack) ? 1 : 0);
				current.setFin((packet.fin) ? 1 : 0);
				current.setRst((packet.rst) ? 1 : 0);
				current.setSyn((packet.syn) ? 1 : 0);
				current.setTotalPackets(1);
				hosts.add(current);
			}
		}
	}
}
