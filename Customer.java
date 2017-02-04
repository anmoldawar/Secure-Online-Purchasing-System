import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.MessageDigest;


public class Customer {
	public static void main(String[] argv) throws Exception{
		
		String hostname = argv[0];
        	String msgfromServer;
        	int flag = 0;
		int portno = Integer.parseInt(argv[1]);
        	Socket ClientSock = new Socket(hostname,portno);

		DataOutputStream write_en = new DataOutputStream(ClientSock.getOutputStream());
       		PrintWriter pw = new PrintWriter(ClientSock.getOutputStream(), true);
        	BufferedReader Reader = new BufferedReader(new InputStreamReader(System.in));
        	BufferedReader in = new BufferedReader(new InputStreamReader(ClientSock.getInputStream()));

		System.out.println("\n**************Welcome to Purchasing Server***********\n");
		String username;
        	System.out.println("Enter username:");
        	username = Reader.readLine();
		boolean correct_password=false;
		
		while(correct_password==false){
			System.out.println("Enter password:");
			String password;
			password = Reader.readLine();

			//Computing the hash of password received
			String hash_pw = SHA1(password);

			//Sending the username and hashed password to the server
			pw.println(username + " " + hash_pw);

			//Server response whether the username and password were correct
			msgfromServer = in.readLine();

			if(msgfromServer.equalsIgnoreCase("OK")){
				flag = 1;
				System.out.println("Correct password");
				correct_password=true;
			}
			else{
				System.out.println("The username/password is incorrect\n Please try again!");
			}
		}

		if(flag == 1){
			
			System.out.println("\n******* Menu ********\n");

			//Receiving the menu from the server		
			while((msgfromServer = in.readLine())!=null){
				if(msgfromServer.equals("end"))
					break;
				else
					System.out.println(msgfromServer);
			}

			System.out.println("\nPlease enter the item number(#) you want to purchase:");
			String item_num = Reader.readLine();
		
     	    		System.out.println("\nEnter quantity:");
			String quantity = Reader.readLine();
			
			String order = item_num+ " " +quantity;
			pw.println(username);

			/*Encrypting the order details(E(Pup,<item||quantity>))*/

			ObjectInputStream keyReader = readPubKeyPsystem();
			PublicKey Key = (PublicKey)keyReader.readObject(); 
			EnDc obj = new EnDc();
			byte[] encrypted = obj.encrypt(order,Key);
			keyReader.close();		

			/*sending the digital signature of the user*/

			Signature sig = Signature.getInstance("MD5WithRSA");
			ObjectInputStream keyReader1 = readuserPri(username);
            		PrivateKey Key1 = (PrivateKey)keyReader1.readObject();
			sig.initSign(Key1);
			byte[] signatureBytes = sig.sign();
			
			ObjectOutputStream wr = new ObjectOutputStream(ClientSock.getOutputStream());
			wr.writeObject(signatureBytes);
			//Digital Signature sent

			//Sending the encrypted order details to Psystem
			wr.writeObject(encrypted);

			System.out.println("\nPlease Enter your Credit card number:");
	            
			String card_number = Reader.readLine();

			String payment = username+" "+card_number;

			//Encrypting the payment details (E(Pup,<name||cardnumber>))

			keyReader = readPubKeyBank();
			Key = (PublicKey)keyReader.readObject();
			byte[] encrypted1 = obj.encrypt(payment,Key);
			keyReader.close();

			// Sending the encrypted payment details(name and card number) to Psystem
			write_en.writeInt(encrypted1.length);
			write_en.write(encrypted1);

			// Checking the response from Server
			msgfromServer = in.readLine();
			if(msgfromServer.equals("OK")){
				System.out.println("We will process your order soon!!!");
			}
			else{
				System.out.println("Wrong credit card number!!!");
			}	
		}
		ClientSock.close();
	}

	/* function to read the public key of Psystem */
	public static ObjectInputStream readPubKeyPsystem() {
		ObjectInputStream keyReader = null;
		try{
		InputStream fis = null;
		fis = new FileInputStream("PsystemPub.key");
		keyReader = new ObjectInputStream(fis);
		}catch(IOException e){
			e.printStackTrace();			
		}
		return keyReader;
	}

	/* function to read the public key of Bank */
	 public static ObjectInputStream readPubKeyBank() {
		ObjectInputStream keyReader = null;
		try{
		InputStream fis = null;
		fis = new FileInputStream("BankPub.key");
		keyReader = new ObjectInputStream(fis);
		}catch(IOException e){
				e.printStackTrace();
		}
		return keyReader;
    }
	
	/* function to read the private key of User */
	public static ObjectInputStream readuserPri(String username) {
        ObjectInputStream keyReader = null;
        try{
			InputStream fis = null;
			if(username.equalsIgnoreCase("alice")){
				fis = new FileInputStream("AlicePri.key");
			}
			if(username.equalsIgnoreCase("tom")){
			fis = new FileInputStream("TomPri.key");
			}
			keyReader = new ObjectInputStream(fis);
        }catch(IOException e){
            e.printStackTrace();
        }
        return keyReader;
    }


	private static String convertToHex(byte[] data)
	{
		StringBuffer buf = new StringBuffer();
		for (int i = 0; i < data.length; i++)
		{
			int halfbyte = (data[i] >>> 4) & 0x0F;
			int two_halfs = 0;
			do
			{
				if ((0 <= halfbyte) && (halfbyte <= 9))
				{
					buf.append((char) ('0' + halfbyte));
				}
				else
				{
					buf.append((char) ('a' + (halfbyte - 10)));
				}
				halfbyte = data[i] & 0x0F;
			} while(two_halfs++ < 1);
		}
		return buf.toString();
	} 

	// function to compute the SHA
 	
	public static String SHA1(String text)throws Exception
	{
		MessageDigest md;
		md = MessageDigest.getInstance("SHA-1");
		byte[] sha1hash = new byte[40];
		md.update(text.getBytes("iso-8859-1"), 0, text.length());
		sha1hash = md.digest();
		return convertToHex(sha1hash);
	}

}
