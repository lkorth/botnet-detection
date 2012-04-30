package botnets;

import java.text.DecimalFormat;

public class Host {

	private String ip;
	private long synack;
	private long fin;
	private long rst;
	private long syn;
	private long totalSent;
	private long totalReceived;

	Host(String ip){
		this.ip = ip;
	}

	public double calculateWorkWeight() {
		DecimalFormat format = new DecimalFormat("#.###");
        return Double.valueOf(format.format((this.synack + this.fin + this.rst + this.syn) / (double) (this.totalSent + this.totalReceived)));
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
	}
	
	public void addToTotalReceived() {
		this.totalReceived++;
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

	public void setIp(String ip) {
		this.ip = ip;
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
