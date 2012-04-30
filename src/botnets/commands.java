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
		}
	}

}
