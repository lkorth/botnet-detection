package botnets;

import java.net.InetAddress;
import java.util.Scanner;

import jpcap.JpcapCaptor;
import jpcap.NetworkInterface;

public class Detection {
	
	final static int adapter = 0;  //may need to be adjusted depending on your adaptors on your computer
	private static PacketHandler ph;
	
	public static void main(String[] args) throws Exception {		
		NetworkInterface[] devices = JpcapCaptor.getDeviceList();
		
		classifyNetwork(devices[adapter].addresses[1].address); // 1 = ip address of adaptor
		
		Scanner scr = new Scanner(System.in);
		(new Thread(new commands(scr, ph))).start();
		
		JpcapCaptor jpcap = JpcapCaptor.openDevice(devices[adapter], 2000, true, 20);
		jpcap.setFilter("ip", true); //only capture IP packets
		jpcap.loopPacket(-1, ph); //capture packets infinitely
	}

	private static void classifyNetwork(InetAddress ip) {
		String delims = "[.]+";
		String[] tokens = ip.getHostAddress().split(delims);
		int first = Integer.parseInt(tokens[0]);
		if(first < 128 && first > 0 )
			ph = new PacketHandler(tokens[0] + ".");
		else if(first < 192 && first > 127)
			ph = new PacketHandler(tokens[0] + "." + tokens[1] + ".");
		else if(first < 224 && first > 191)
			ph = new PacketHandler(tokens[0] + "." + tokens[1] + "." + tokens[2] + ".");
		else
			ph = new PacketHandler(tokens[0] + "." + tokens[1] + ".");
	}
}
