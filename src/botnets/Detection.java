package botnets;

import java.net.InetAddress;

import jpcap.JpcapCaptor;
import jpcap.NetworkInterface;

public class Detection {
	
	final static int adaptor = 1;
	
	public static void main(String[] args) throws Exception {
		NetworkInterface[] devices = JpcapCaptor.getDeviceList();
		
		String localNetwork = classifyNetwork(devices[adaptor].addresses[1].address); // 1 = ip address of adaptor
		
		JpcapCaptor jpcap = JpcapCaptor.openDevice(devices[adaptor], 2000, true, 20);
		jpcap.setFilter("ip", true); //only capture IP packets
		jpcap.loopPacket(-1, new PacketHandler()); //capture packets infinitely 
	}

	private static String classifyNetwork(InetAddress ip) {
		String delims = "[.]+";
		String[] tokens = ip.getHostAddress().split(delims);
		int first = Integer.parseInt(tokens[0]);
		if(first < 128 && first > 0 )
			return tokens[0];
		else if(first < 192 && first > 127)
			return tokens[0] + "." + tokens[1];
		else if(first < 224 && first > 191)
			return tokens[0] + "." + tokens[1] + "." + tokens[2];
		return tokens[0] + "." + tokens[1];
	}
}
