package botnets;

import java.net.InetAddress;

import jpcap.PacketReceiver;
import jpcap.packet.Packet;
import jpcap.packet.UDPPacket;

class PacketHandler implements PacketReceiver {
	
	private String localNetwork;
	
	PacketHandler(String localNetwork){
		this.localNetwork = localNetwork;
	}
	
	//this method is called every time Jpcap captures a packet
	public void receivePacket(Packet packet) {		
		if(packet.header[23] == 17) { //udp packets (IP Packet protocol 17)
			UDPPacket p = (UDPPacket) packet;
			if(p.dst_port == 53) { //dns outbound queries only
				System.out.println(convert(p.data)); //print data of dns query
			}
		}
	}
	
	//Conversation from byte[] to string
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
}
