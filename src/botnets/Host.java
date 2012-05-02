package botnets;

import java.text.DecimalFormat;
import java.util.ArrayList;

public class Host {

	private String ip;
	private long synack;
	private long fin;
	private long rst;
	private long syn;
	private long totalSent;
	private long totalReceived;
	private double maxWorkWeight = 0;
	private int count = 0;
	public ArrayList<String> httpRequests;
	
	Host(String ip){
		this.ip = ip;
		this.httpRequests = new ArrayList<String>();
	}

	public double printWorkWeight() {
		DecimalFormat format = new DecimalFormat("#.####");
        return Double.valueOf(format.format((this.synack + this.fin + this.rst + this.syn) / (double) (this.totalSent + this.totalReceived)));
	}
	
	public void checkWorkWeight() {
		DecimalFormat format = new DecimalFormat("#.####");
        double tmp = Double.valueOf(format.format((this.synack + this.fin + this.rst + this.syn) / (double) (this.totalSent + this.totalReceived)));
        if(tmp > this.maxWorkWeight)
        	this.maxWorkWeight = tmp;
	}
	
	public String printPacketCounts() {
		return (new String("Syn: " + this.syn + " SynAck: " + this.synack + " Fin: " + this.fin + " Rst: " + this.rst + " Total Sent: " + this.totalSent + " Total Received: " + this.totalReceived));
	}
	
	public void addSynAck() {
		this.synack++;
	}

	public void addFin() {
		this.fin++;
	}

	public void addRst() {
		this.rst++;
	}

	public void addSyn() {
		this.syn++;
	}
	
	public void addToTotalSent() {
		this.totalSent++;
		if(this.count > 50)
			checkWorkWeight();
		else
			this.count++;
	}
	
	public void addToTotalReceived() {
		this.totalReceived++;
		if(this.count > 50)
			checkWorkWeight();
		else
			this.count++;
	}
	
	public boolean equals(Object obj) {
		if(obj instanceof Host) {
			Host h = (Host) obj;
			return h.getIp().equals(this.ip);
		}
		else
			return false;
	}
	
	public String getIp() {
		return ip;
	}
	
	public long getSynAck() {
		return synack;
	}

	public void setSynAck(long synack) {
		this.synack = synack;
	}

	public long getFin() {
		return fin;
	}

	public void setFin(long fin) {
		this.fin = fin;
	}

	public long getRst() {
		return rst;
	}

	public void setRst(long rst) {
		this.rst = rst;
	}

	public long getSyn() {
		return syn;
	}

	public void setSyn(long syn) {
		this.syn = syn;
	}
	
	public long getTotalSent() {
		return totalSent;
	}

	public void setTotalSent(long totalSent) {
		this.totalSent = totalSent;
	}
	
	public long getTotalReceived() {
		return totalReceived;
	}
	
	public void setTotalReceived(long totalReceived) {
		this.totalReceived = totalReceived;
	}
}
