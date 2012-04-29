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
			if(scr.nextLine().trim().equals("printww")) {
				System.out.println("Current Weights:");
				ph.printWorkWeights();
			}
		}
	}

}
