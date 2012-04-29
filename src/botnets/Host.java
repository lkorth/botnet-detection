package botnets;

public class Host {

	private String ip;
	private long ack;
	private long fin;
	private long rst;
	private long syn;
	private long totalPackets;

	Host(String ip){
		this.ip = ip;
	}

	public double calculateWorkWeight() {
		return ((this.ack + this.fin + this.rst + this.syn) / this.totalPackets);
	}
	
	public void addAck() {
		this.ack++;
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
	
	public void addToTotal() {
		this.totalPackets++;
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
	
	public long getAck() {
		return ack;
	}

	public void setAck(long ack) {
		this.ack = ack;
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
	
	public long getTotalPackets() {
		return totalPackets;
	}

	public void setTotalPackets(long totalPackets) {
		this.totalPackets = totalPackets;
	}
}
