package botnets;

import java.util.ArrayList;

public class DNSQuery {
	
	public ArrayList<DNSHostInfo> hostsInfo;
	private String query;

	DNSQuery(String query){
		this.query = query;
	}
	
	public boolean equals(Object obj) {
		if(obj instanceof DNSQuery) {
			DNSQuery d = (DNSQuery) obj;
			return d.getQuery().equals(this.query);
		}
		else
			return false;
	}
	
	public String getQuery() {
		return query;
	}

}

class DNSHostInfo {
	private String ip;
	public ArrayList<Long> timeStamp;
	
	DNSHostInfo(String ip){
		this.ip = ip;
		this.timeStamp = new ArrayList<Long>();
	}
	
	public boolean equals(Object obj) {
		if(obj instanceof DNSHostInfo) {
			DNSHostInfo d = (DNSHostInfo) obj;
			return d.getIp().equals(this.ip);
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
}
