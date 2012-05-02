package botnets;

import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Iterator;

import jpcap.PacketReceiver;
import jpcap.packet.Packet;
import jpcap.packet.TCPPacket;
import jpcap.packet.UDPPacket;

class PacketHandler implements PacketReceiver {
	
	private String localNetwork;
	public ArrayList<Host> hosts;
	private ArrayList<Channel> channels;
	public ArrayList<DNSQuery> currentTimePeriodDNSQueries;
	public ArrayList<DNSQuery> previousTimePeriodDNSQueries;
	private ArrayList<String> whiteList;
	private ArrayList<String> suspectedBotnetQueries;
	private long nextTimePeriod;
	private int sizeThreshold; 
	
	PacketHandler(String localNetwork){
		this.localNetwork = localNetwork;
		this.hosts = new ArrayList<Host>();
		this.currentTimePeriodDNSQueries = new ArrayList<DNSQuery>();
		this.previousTimePeriodDNSQueries = new ArrayList<DNSQuery>();
		this.whiteList = new ArrayList<String>();
		this.suspectedBotnetQueries = new ArrayList<String>();
		this.nextTimePeriod = System.currentTimeMillis() + (60 * 60 * 1000); //1 hr: 60 min/hr * 60 sec/min * 1000mills/sec
		this.sizeThreshold = 7;
	}
	
	//this method is called every time Jpcap captures a packet
	public void receivePacket(Packet packet) {	
		//TODO compare non local network with blacklist/white list
		
		if(packet.header[23] == 17) { //udp packets (IP Packet protocol 17)
			UDPPacket p = (UDPPacket) packet;
			if(p.dst_port == 53) { //dns outbound queries only
				processQuery(p);
			}
		}
		else if(packet.header[23] == 6) { //tcp packets (IP Packet protocol 6)
			TCPPacket p = (TCPPacket) packet;
			storeWorkWeight(p);
			checkForIRC(p);
			String data = new String(p.data);
			if(data.toLowerCase().startsWith("get") || data.toLowerCase().startsWith("post")) {
				storeHttpRequest(p);
			}
				
		}
	}
	
	private void storeHttpRequest(TCPPacket packet) {
		Host current = new Host(packet.src_ip.getHostAddress());
		int index = hosts.indexOf(current); //host will already exist because of storeWorkWeight call
		hosts.get(index).httpRequests.add(new String(packet.data) + "Time: " + System.currentTimeMillis());
	}

	private boolean isLocalNetwork(InetAddress ip) {
		return ip.getHostAddress().startsWith(localNetwork);
	}
	
	public void processQuery(UDPPacket packet) {
		String convertedQuery = convert(packet.data);
		DNSQuery currentQuery = new DNSQuery(convertedQuery);
		if(this.whiteList.indexOf(convertedQuery) == -1) { //only process if domain is not white listed
			//check to see if host exists
			Host host = new Host(packet.src_ip.getHostAddress());
			int index = hosts.indexOf(host);
			if(index == -1) { //if host does not exist, create new one
				host.setSynAck(0);
				host.setFin(0);
				host.setRst(0);
				host.setSyn(0);
				host.setTotalSent(0);
				hosts.add(host);
				index = hosts.indexOf(host);
			}
			int queryIndex = this.currentTimePeriodDNSQueries.indexOf(currentQuery); //check if dns query exists
			if(queryIndex != -1) {
				int hostIndex = this.currentTimePeriodDNSQueries.get(queryIndex).hostsInfo.indexOf(packet.src_ip.getHostAddress()); //check if host is associate with query
				if(hostIndex != -1) {
					this.currentTimePeriodDNSQueries.get(queryIndex).hostsInfo.get(hostIndex).timeStamp.add(System.currentTimeMillis()); //add timestamp 
				}
				else {
					DNSHostInfo tmpHost = new DNSHostInfo (packet.src_ip.getHostAddress());
					tmpHost.timeStamp.add(System.currentTimeMillis());
					this.currentTimePeriodDNSQueries.get(queryIndex).hostsInfo.add(tmpHost);
				}
			}
			else { //if query does not exist, create one
				this.currentTimePeriodDNSQueries.add(currentQuery);
				queryIndex = this.currentTimePeriodDNSQueries.indexOf(currentQuery);
				DNSHostInfo tmpHost = new DNSHostInfo (packet.src_ip.getHostAddress());
				tmpHost.timeStamp.add(System.currentTimeMillis());
				this.currentTimePeriodDNSQueries.get(queryIndex).hostsInfo.add(tmpHost);
			}
		}
		if(System.currentTimeMillis() >= nextTimePeriod) {
			processDNS();
		}
	}
	
	private void processDNS() {  //Alg developed here: http://ccs.korea.ac.kr/pds/CIT07.pdf
		//copy dns queries for last hour and clear
		if(this.previousTimePeriodDNSQueries.size() < 1) {
			ArrayList<DNSQuery> previousTimePeriodDNSQueries = (ArrayList<DNSQuery>) this.currentTimePeriodDNSQueries.clone();
			this.currentTimePeriodDNSQueries = new ArrayList<DNSQuery>();
		}
		else {
			ArrayList<DNSQuery> toProcess = (ArrayList<DNSQuery>) this.previousTimePeriodDNSQueries.clone();
			ArrayList<DNSQuery> previousTimePeriodDNSQueries = (ArrayList<DNSQuery>) this.currentTimePeriodDNSQueries.clone();
			this.currentTimePeriodDNSQueries = new ArrayList<DNSQuery>();
			
			ArrayList<DNSQuery> intersection = intersection(toProcess, previousTimePeriodDNSQueries);
			
			Iterator<DNSQuery> itr = intersection.iterator();
			while(itr.hasNext()) {
				DNSQuery tmp = itr.next();
				if(tmp.hostsInfo.size() < this.sizeThreshold) //TODO whitelist if under size?
					itr.remove();
				else {
					DNSQuery process = toProcess.get(toProcess.indexOf(tmp));
					DNSQuery previousTime = previousTimePeriodDNSQueries.get(previousTimePeriodDNSQueries.indexOf(tmp));
					double similarity = calculateSimilarity(process, previousTime);
					if(similarity != -1 && similarity < 0.15)
						this.suspectedBotnetQueries.add(tmp.getQuery());
					else if(similarity != -1 && similarity > 0.85)
						this.whiteList.add(tmp.getQuery());
				}
			}
		}
		
		//reset times
		this.nextTimePeriod = System.currentTimeMillis() + (60 * 60 * 1000); //1 hr: 60 min/hr * 60 sec/min * 1000mills/sec
	}
	
	private double calculateSimilarity(DNSQuery process, DNSQuery previousTime) {
		int A = process.hostsInfo.size();
		int B = previousTime.hostsInfo.size();
		int C = intersection(process.hostsInfo, previousTime.hostsInfo).size();
		
		if(A == 0 || B == 0)
			return -1;
		else {
			return (0.5 * (((double) C/A) + ((double) C/B)));
		}
	}
	
	public <T> ArrayList<T> intersection(ArrayList<T> list1, ArrayList<T> list2) {
        ArrayList<T> list = new ArrayList<T>();

        for (T t : list1) {
            if(list2.contains(t)) {
                list.add(t);
            }
        }
        return list;
    }

	private void storeWorkWeight(TCPPacket packet) { //Described in paper here: http://web.cecs.pdx.edu/~jrb/jrb.papers/sruti06/sruti06.pdf
		if(isLocalNetwork(packet.src_ip)) {
			Host current = new Host(packet.src_ip.getHostAddress());
			int index = hosts.indexOf(current);
			if(index != -1) {
				if(packet.ack && packet.syn)
					hosts.get(index).addSynAck();
				else if(packet.syn)
					hosts.get(index).addSyn();
				if(packet.fin)
					hosts.get(index).addFin();
				hosts.get(index).addToTotalSent();
			}
			else {
				current.setSynAck((packet.ack && packet.syn) ? 1 : 0);
				current.setFin((packet.fin) ? 1 : 0);
				current.setRst(0);
				current.setSyn((packet.syn && !packet.ack) ? 1 : 0);
				current.setTotalSent(1);
				hosts.add(current);
			}
		}
		else {
			Host current = new Host(packet.dst_ip.getHostAddress());
			int index = hosts.indexOf(current);
			if(index != -1) {
				if(packet.rst)
					hosts.get(index).addRst();
				if(packet.fin)
					hosts.get(index).addFin();
				hosts.get(index).addToTotalReceived();
			}
			else {
				current.setSynAck(0);
				current.setFin((packet.fin) ? 1 : 0);
				current.setRst((packet.rst) ? 1 : 0);
				current.setSyn(0);
				current.setTotalReceived(1);
				hosts.add(current);
			}
		}
	}
	
	private void checkForIRC(TCPPacket p) {
		String data = new String(p.data).toLowerCase();
		if(data.startsWith("join")) {
			Channel current = new Channel(data.substring(5), p.dst_ip.getHostAddress() + p.dst_port);
			int index = channels.indexOf(current);
			if(index != -1) {
				channels.get(index).addJoin();
			}
			else {
				channels.add(current);
			}
		}
		else if(data.startsWith("ping")) {
			Channel current = new Channel(null, p.dst_ip.getHostAddress() + p.dst_port);
			int index = channels.indexOf(current);
			if(index != -1) {
				channels.get(index).addPing();
			}
		}
		else if(data.startsWith("pong")) {
			Channel current = new Channel(null, p.dst_ip.getHostAddress() + p.dst_port);
			int index = channels.indexOf(current);
			if(index != -1) {
				channels.get(index).addPong();
			}
		}
		else if(data.startsWith("privmsg")) {
			Channel current = new Channel(null, p.dst_ip.getHostAddress() + p.dst_port);
			int index = channels.indexOf(current);
			if(index != -1) {
				channels.get(index).addPrivmsg();
			}
		}
	}
	
	private void calculateEntropy(TCPPacket p) {
		//TODO Calculate entropy of the packet data
	}
	
	//Conversation from byte[] to dns query. Adapted from http://www.highonphp.com/decoding-udp-dns-requests and http://stackoverflow.com/questions/2201930/convert-ascii-byte-to-string
	private String convert(byte[] data) {
	    StringBuilder sb = new StringBuilder(data.length);
	    for (int i = 13; i < data.length-5; ++ i) {
	        if (data[i] < 0) throw new IllegalArgumentException();
	        else if (data[i] < 32) sb.append('.');
	        else if (data[i] > 32 && data[i] < 127) sb.append((char) data[i]);
	    }
	    return sb.toString();
	}

	public void printWorkWeights() {
		ArrayList<Host> tmp = hosts;
		Iterator<Host> itr = tmp.iterator();
		while(itr.hasNext()) {
			Host h = itr.next();
			System.out.println(h.getIp() + ": " + h.printWorkWeight());
		}
	}
	
	public void printPacketCounts() {
		Iterator<Host> itr = ((ArrayList<Host>) hosts.clone()).iterator();
		while(itr.hasNext()) {
			Host h = itr.next();
			System.out.println(h.getIp() + ": " + h.printPacketCounts());
		}
	}

	public void printWhitelist() {
		Iterator<String> itr = ((ArrayList<String>) whiteList.clone()).iterator();
		while(itr.hasNext()) {
			String d = itr.next();
			System.out.println(d);
		}
	}

	public void printBotQueries() {
		Iterator<String> itr = ((ArrayList<String>) suspectedBotnetQueries.clone()).iterator();
		while(itr.hasNext()) {
			String d = itr.next();
			System.out.println(d);
		}
	}

	public void printIRC() {
		Iterator<Channel> itr = ((ArrayList<Channel>) channels.clone()).iterator();
		while(itr.hasNext()) {
			Channel c = itr.next();
			System.out.println(c.getChannel());
		}
	}

	public void printDNSQueries() {
		Iterator<DNSQuery> itr = ((ArrayList<DNSQuery>) currentTimePeriodDNSQueries.clone()).iterator();
		while(itr.hasNext()) {
			DNSQuery d = itr.next();
			System.out.println(d.getQuery());
		}
	}
}
