package botnets;

import java.util.Scanner;

public class commands implements Runnable {
	
	Scanner scr;
	PacketHandler ph;
	
	commands(Scanner scr, PacketHandler ph) {
		this.scr = scr;
		this.ph = ph;
	}

	@Override
	public void run() {
		while(true) {
			String entered = scr.nextLine().trim();
			if(entered.equals("printww")) {
				System.out.println("Current Weights:");
				ph.printWorkWeights();
			}
			else if(entered.equals("printpc")) {
				System.out.println("Current Packet Counts:");
				ph.printPacketCounts();
			}
			else if(entered.equals("printwl")) {
				System.out.println("Current Whitelist:");
				ph.printWhitelist();
			}
			else if(entered.equals("printqueries")) {
				System.out.println("Current DNS queries:");
				ph.printDNSQueries();
			}
			else if(entered.equals("printbotqueries")) {
				System.out.println("Current suspected bot dns queries:");
				ph.printBotQueries();
			}
			else if(entered.equals("printIRC")) {
				System.out.println("Current IRC Channels and hosts:");
				ph.printIRC();
			}
		}
	}

}
