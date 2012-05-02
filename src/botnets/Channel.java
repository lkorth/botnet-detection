package botnets;

public class Channel {
	
	private String channel;
	private String ipAndPort;
	private long join;
	private long ping;
	private long pong;
	private long privmsg;
	
	Channel(String channel, String ipAndPort){
		this.channel = channel;
		this.ipAndPort = ipAndPort;
		this.join = 1;
		this.ping = 0;
		this.pong = 0;
		this.privmsg = 0;
	}
	
	public boolean equals(Object obj) {
		if(obj instanceof Channel) {
			Channel c = (Channel) obj;
			return c.getIpAndPort().equals(this.ipAndPort);
		}
		else
			return false;
	}

	public String getChannel() {
		return channel;
	}
	
	public String getIpAndPort() {
		return ipAndPort;
	}

	public long getJoin() {
		return join;
	}

	public void setJoin(long join) {
		this.join = join;
	}
	
	public void addJoin() {
		this.join++;
	}

	public long getPing() {
		return ping;
	}

	public void setPing(long ping) {
		this.ping = ping;
	}
	
	public void addPing() {
		this.ping++;
	}

	public long getPong() {
		return pong;
	}

	public void setPong(long pong) {
		this.pong = pong;
	}
	
	public void addPong() {
		this.pong++;
	}

	public long getPrivmsg() {
		return privmsg;
	}

	public void setPrivmsg(long privmsg) {
		this.privmsg = privmsg;
	}
	
	public void addPrivmsg() {
		this.privmsg++;
	}

}
