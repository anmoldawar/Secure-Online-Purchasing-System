import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;



public class Psystem {
	public static void main(String[] argv) throws Exception{
		if(argv.length == 0) {
			return;
		}
		
		String msgfromClient;

		//Connection from Psystem to Customer
		ServerSocket s = new ServerSocket(Integer.parseInt(argv[0]));
		System.out.println("Waiting for client to connect....");

	while(true){
		Socket conn = s.accept();
		System.out.println("Client Connected");

		DataInputStream read_en = new DataInputStream(conn.getInputStream());
		BufferedReader in = new BufferedReader(new InputStreamReader(conn.getInputStream()));

		//Connection from Psystem to Bank
		String hostname = argv[1];
		int portno = Integer.parseInt(argv[2]);

		Socket ClientSock = new Socket(hostname,portno);
		BufferedReader cli = new BufferedReader(new InputStreamReader(ClientSock.getInputStream()));
		DataOutputStream RSAWriter = new DataOutputStream(ClientSock.getOutputStream());
		PrintWriter pw = new PrintWriter(conn.getOutputStream(), true);

		String oldfilename = "item.txt";
	        String tmpfilename = "item_temp.txt";

		StringBuilder sb = new StringBuilder();
		int counter=0;
	
		String [] fileInfo = new String[10];
		int i = 0;
		String str;
		BufferedReader br=null;

		while(counter==0)
		{
			//receving username and password from Customer

			msgfromClient = in.readLine();

			String u_info[] = msgfromClient.split(" ");
			String h_pw = u_info[1];
			i=0;
			br= new BufferedReader(new FileReader("password.txt"));

			while ((str = br.readLine()) != null){
				fileInfo[i] = str;
				i++;
			}

			//checking if the hashed password from the customer and in the file are same
			for(int n=0;n<fileInfo.length;n=n+2){
				int m = n+1;

				if(fileInfo[m]!=null){
					String ps = fileInfo[m];				
					if((h_pw.equals(ps) &&(u_info[0].equals(fileInfo[n])))){
						pw.println("OK");
						//passwords match
						counter = 1;
						break;
					}
				}

			}
		
			if(counter == 0){
				pw.println("error");
				//passwords do not match
			}
			br.close();
		}

		if(counter==1){
			
			//System.out.println("Valid user");
			
			BufferedReader br1 = new BufferedReader(new FileReader(oldfilename));
			String strLine,price=null;
			
			//reading the contents of file item and sending it to the Customer
			while ((strLine = br1.readLine()) != null){
				pw.println(strLine); 
				sb.append(strLine);
				sb.append(", ");
			}
			pw.println("end");
			br1.close();

			String username = in.readLine();

			ObjectInputStream wi = new ObjectInputStream(conn.getInputStream());

			//receiving the Digital Signature
			byte[] order = (byte []) wi.readObject();
			
			// Verifying the DS
			Signature sig = Signature.getInstance("MD5WithRSA");
			ObjectInputStream keyReader1 = readPubKeyuser(username);
			PublicKey key1 = (PublicKey) keyReader1.readObject();
			sig.initVerify(key1);
			boolean result = sig.verify(order);
			
			if(result==true){
				//System.out.println("User Verfied");
			
				//decrypting the order details sent by the cutomer with private key of Psystem
				ObjectInputStream keyReader = readPsystemPri();
				PrivateKey PriKey = (PrivateKey)keyReader.readObject();
				byte[] order1 = (byte []) wi.readObject();
				EnDc obj = new EnDc();
				final String decrypted = obj.decrypt(order1, PriKey);
				keyReader.close();

				String orderInfo[] = decrypted.split(" ");

				int item_num = Integer.parseInt(orderInfo[0]);
				int quantity = Integer.parseInt(orderInfo[1]);

				String menustr = sb.toString();
				menustr = menustr.replace(", "," ");
				String menu[] = menustr.split(" ");

				int j;

				// Calculating price for a valid item
				for(j=0;j<menu.length;j=j+4){
					if(orderInfo[0].equals(menu[j])){
						price = menu[j+2];
						//menu[j+3] = ""+ (Integer.parseInt(menu[j+3])-quantity);
						break;
					}
           			}

				int total=0;

				//calculating the price of the order
				if(price!=null){
					total = quantity * (Integer.parseInt(price.substring(1)));
				}

				String totalPrice = ""+total;

				//encrypting the total price with the private key of Psystem

				ObjectInputStream keyReader2 = readPsystemPri();
				PrivateKey Key1 = (PrivateKey)keyReader2.readObject();
				byte[] encryptedPrice = obj.encryptwithPrivate(totalPrice,Key1);
				keyReader2.close();

				//sending the encrypted total price 
				RSAWriter.writeInt(encryptedPrice.length);
				RSAWriter.write(encryptedPrice);

				//Receiving the encrypted username and card details from customer
				byte[] payment = null;
				int len = read_en.readInt();
                        
				if(len>0){
	                                payment = new byte[len];
	                                read_en.readFully(payment, 0, payment.length);
        	                }

				//Sending the encrypted username and card details from customer
				RSAWriter.writeInt(payment.length);
				RSAWriter.write(payment);
			
				BufferedWriter bw = new BufferedWriter(new FileWriter(tmpfilename));
			
				//Receiving the response from bank after it has verified the username and cardnumber
				String msgfromBank;
				msgfromBank = cli.readLine();

				if(msgfromBank.equals("OK")){
					pw.println("OK");

					//updating the quantity of item
					menu[j+3] = ""+ (Integer.parseInt(menu[j+3])-quantity);

					int cnt =0;
					for(int p=0;p<menu.length;p++){
						if(cnt<=2){
							bw.write(menu[p]);
							bw.write(", ");
							cnt++;
						}
						else{	
							bw.write(menu[p]);
							bw.write("\n");
							cnt = 0;
						}					
					}
				
				//updating the file
				File oldFile = new File(oldfilename);
		    		oldFile.delete();			

				File newFile = new File(tmpfilename);
				newFile.renameTo(oldFile);
				//bw.close();		

				}
			else{
				pw.println("error");
			}
			bw.close();

		}
	}		
			conn.close();		
			break;

	}
	}

	//function for reading the publick key of Psystem
	public static ObjectInputStream readPsystemPri() {
		ObjectInputStream keyReader = null;
		try{
		InputStream fis = null;
		fis = new FileInputStream("PsystemPri.key");
		keyReader = new ObjectInputStream(fis);
		}catch(IOException e){
			e.printStackTrace();
		}
		return keyReader;
	}

	//function for reading the public key of user(Alice or Tom)
	public static ObjectInputStream readPubKeyuser(String username) {
		ObjectInputStream keyReader = null;
		try{
			InputStream fis = null;
			if(username.equalsIgnoreCase("alice")){
			   fis = new FileInputStream("AlicePub.key");
			}
			if(username.equalsIgnoreCase("tom")){
				fis = new FileInputStream("TomPub.key");
			}
			keyReader = new ObjectInputStream(fis);
		}catch(IOException e){
			e.printStackTrace();
		}
		return keyReader;
    }
}

