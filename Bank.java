import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.PrivateKey;
import java.security.PublicKey;

public class Bank {
    public static void main(String[] argv) throws Exception{
		if(argv.length == 0) {
				return;
		}

		ServerSocket sBank = new ServerSocket(Integer.parseInt(argv[0]));
		System.out.println("Waiting for client(Psystem) to connect....");
		while(true){
			Socket conn = sBank.accept();
			System.out.println("Client(Psystem) Connected");

			PrintWriter pw = new PrintWriter(conn.getOutputStream(), true);
			DataInputStream read_en = new DataInputStream(conn.getInputStream());

			String oldfilename = "balance.txt";
			String tmpfilename = "temp.txt";

			StringBuilder sb = new StringBuilder();		
			int flag=0,total=0;

			//reading the encrpted value of total price
			byte[] totalPrice = null;
			int len = read_en.readInt();
			if(len>0){
				totalPrice = new byte[len];
					read_en.readFully(totalPrice, 0, totalPrice.length);
			}

			//Receiving the payment details(username and card number)
			byte[] payment = null;

			int length = read_en.readInt();
			if(length>0){
				payment = new byte[length];
				read_en.readFully(payment, 0, payment.length);
			}

			//decrypting the username and car number with private key of bank
			ObjectInputStream keyReader = readBankPri();
			PrivateKey PriKey = (PrivateKey)keyReader.readObject();
			EnDc obj = new EnDc();
			String decrypted = obj.decrypt(payment, PriKey);
			keyReader.close();

			String paymentInfo[] = decrypted.split(" ");
			String username = paymentInfo[0];
			String card_number = paymentInfo[1];

			BufferedReader br = new BufferedReader(new FileReader(oldfilename));
			BufferedWriter bw = new BufferedWriter(new FileWriter(tmpfilename));
			String str;

			while((str = br.readLine())!=null){
				String fileInfo[] = str.split(", ",3);

				if((fileInfo[1].equals(card_number)) &&(fileInfo[0].equals(username))){
					pw.println("OK");
					flag=1;
		
					//decrypting the total price with public key of Psystem
					ObjectInputStream keyReader1 = readPubKeyPsystem();
		                	PublicKey PubKey = (PublicKey)keyReader1.readObject();
        		        	EnDc obj1 = new EnDc();
                			String decryptedPrice = obj1.decryptwithPublic(totalPrice, PubKey);
                			keyReader1.close();

                			total = Integer.parseInt(decryptedPrice);

					//updating the credit balance
					fileInfo[2] = ""+(Integer.parseInt(fileInfo[2])+total);
					for(int i=0;i<fileInfo.length;i++){
						if(i<2){
							sb.append(fileInfo[i]+", ");
							//bw.write(sb.toString());
						}
						else{
							sb.append(fileInfo[i]+"\n");
							//bw.write(sb.toString());
						}
					}
				}
				else{
					sb.append(str+"\n");
				}
		
			}		
			
			if(flag!=1){
				pw.println("error");
			}
	
			bw.write(sb.toString());
			File oldFile = new File(oldfilename);
      			oldFile.delete();

      			File newFile = new File(tmpfilename);
      			newFile.renameTo(oldFile);

			br.close();
			bw.close();
			conn.close();
			break;
			}
			
		}

	//function to read the private key of bank
	public static ObjectInputStream readBankPri() {
                ObjectInputStream keyReader = null;
                try{
                InputStream fis = null;
                fis = new FileInputStream("BankPri.key");
                keyReader = new ObjectInputStream(fis);
                }catch(IOException e){
                        e.printStackTrace();
                }
                return keyReader;
	}

	//function to read the public key of Psystem
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



}
