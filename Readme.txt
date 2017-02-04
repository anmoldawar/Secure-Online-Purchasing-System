Name: Anmol Dawar
email id: adawar1@binghamton.edu

Project implemented individually. No partner.

Language Used: Java

Code tested on bingsuns.

Note: As per discussion with Professor, the system is programmed for valid inputs only. Invalid inputs will give 
exceptions. Password and credit card number error handling is done as written in the project document.


Instructions to compile and run:
1. Compile the code using makefile (make command).
2. Run the Bank server with the command: java Bank 9699
3. Run the Psystem with the command: java Psystem 9698 bingsuns.cc,binghamton.edu 9699
4. Run the client as: java Customer bingsuns.cc,binghamton.edu 9698



Reference for Key generation, RSA encyrption and decryption: 
https://javadigest.wordpress.com/2012/08/26/rsa-encryption-example/

Reference for SHA algorithm
http://www.anyexample.com/programming/java/java_simple_class_to_compute_sha_1_hash.xml



Code for key generation:


public static void generateKey() {
    try {
      final KeyPairGenerator keyGen = KeyPairGenerator.getInstance(ALGORITHM);
      keyGen.initialize(1024);
      final KeyPair key = keyGen.generateKeyPair();
      File privateKeyFile = new File(PRIVATE_KEY_FILE);
      File publicKeyFile = new File(PUBLIC_KEY_FILE);
      // Create files to store public and private key
      if (privateKeyFile.getParentFile() != null) {
        privateKeyFile.getParentFile().mkdirs();
      }
      privateKeyFile.createNewFile();
      if (publicKeyFile.getParentFile() != null) {
        publicKeyFile.getParentFile().mkdirs();
      }
      publicKeyFile.createNewFile();
      // Saving the Public key in a file
      ObjectOutputStream publicKeyOS = new ObjectOutputStream(
          new FileOutputStream(publicKeyFile));
      publicKeyOS.writeObject(key.getPublic());
      publicKeyOS.close();
      // Saving the Private key in a file
      ObjectOutputStream privateKeyOS = new ObjectOutputStream(
          new FileOutputStream(privateKeyFile));
      privateKeyOS.writeObject(key.getPrivate());
      privateKeyOS.close();
    } catch (Exception e) {
      e.printStackTrace();
    }
  }



code for encryption/decryption:

 public static synchronized byte[] encrypt(String text, PublicKey key) {
    byte[] cipherText = null;
    try {
      // get an RSA cipher object and print the provider
      final Cipher cipher = Cipher.getInstance(ALGORITHM);
      // encrypt the plain text using the public key
      cipher.init(Cipher.ENCRYPT_MODE, key);
      cipherText = cipher.doFinal(text.getBytes());
    } catch (Exception e) {
      e.printStackTrace();
    }
    return cipherText;
  }
  /**
   * Decrypt text using private key.
   *
   * @param text
   * :encrypted text
   * @param key
   * :The private key
   * @return plain text
   * @throws java.lang.Exception
   */
  public static synchronized String decrypt(byte[] text, PrivateKey key) {
    byte[] decryptedText = null;
    try {
      // get an RSA cipher object and print the provider
      final Cipher cipher = Cipher.getInstance(ALGORITHM);
      // decrypt the text using the private key
      cipher.init(Cipher.DECRYPT_MODE, key);
      decryptedText = cipher.doFinal(text);
    } catch (Exception ex) {
      ex.printStackTrace();
    }
    return new String(decryptedText);
  }



Core code for DS:

	//Generating the DS	
 	Signature sig = Signature.getInstance("MD5WithRSA");
        ObjectInputStream keyReader1 = readuserPri(username);
        PrivateKey Key1 = (PrivateKey)keyReader1.readObject();
        sig.initSign(Key1);
        byte[] signatureBytes = sig.sign();

	//Verification 
	 Signature sig = Signature.getInstance("MD5WithRSA");
         ObjectInputStream keyReader1 = readPubKeyuser(username);
         PublicKey key1 = (PublicKey) keyReader1.readObject();
         sig.initVerify(key1);
         boolean result = sig.verify(order);

