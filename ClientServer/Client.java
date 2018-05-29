/**
 * This application uses in built functions of various cryptographic algorithms. 
 * References that has been used on order to develop this program are:-
 * 1)https://sites.google.com/a/uah.edu/pervasive-security-privacy/node-level/cryptographic-algorithms-using-java
 * 2)https://docs.oracle.com/javase/tutorial/networking/sockets/readingWriting.html
 * 3)Java Cryptography by Jonathan Knudsen
 * 4)Size for AES in this case is 128 bits as 256 is only supported in Java 9
 */

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Scanner;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

import java.security.*;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;

/**
 * @author Sunit Tiwari
 *
 */
public class Client {
// Declaring all the variables as global 
	public Key key;
	private static KeyPair keyPair;
	private static Cipher cipher = null;
	public static String plaintext = null;
	public static long time1 = 0;
	public static long time2 = 0;
	int size = 128;
	private static byte[] encryptedBytes = null;
	private static byte[] encryptedBytesaes = null;
	private static byte[] decryptedBytes = null;
	private static byte[] keyBytes = null;
	private static byte[] keyBytessign = null;
	private static Signature signature;
	private static KeyPair keyPairsignature;
	private static byte[] sign;
	public static Client methodcall = new Client();

	/**
	 * @param args
	 * @throws IOException
	 * @throws UnknownHostException
	 * @throws NoSuchAlgorithmException
	 */
	public static void main(String[] args) throws UnknownHostException, IOException, NoSuchAlgorithmException {
// In this we get the input from the user which is used as the plain text.
		Scanner scanner = new Scanner(System.in);
		System.out.println("Enter your name");
		String input = scanner.nextLine(); //Stores the input provided by the user in a string with the help of scanner class

		System.out.println("Welcome" +"@" +input );
	
		Scanner scannerplain = new Scanner(System.in);
		Socket splaintext = new Socket("localhost", 4545);
		Scanner scplain = new Scanner(splaintext.getInputStream()); 
		System.out.println("Enter the text that you intend to encrypt");
		plaintext = scannerplain.nextLine();
		PrintStream ps = new PrintStream(splaintext.getOutputStream());
		ps.println(plaintext);
	
	
		
	// If an empty input is provided by the user	
		if(plaintext.length()==0)
		{
			System.out.println("Please enter a phrase to start");
			System.exit(0);
			
		}
		//Calling all the cryptographic functions
		methodcall.symetric();
		methodcall.rsaencyrption();
		methodcall.digitalsignature();
		methodcall.hashfunction();
		
		
	}

	// This function calls the inbuilt symetric key function which generates a key and encrpts the plain text
	public void symetric() throws UnknownHostException, IOException {
// Creating socket and establishing a connection with the server. Please note the change in the port number
		Socket ss = new Socket("localhost", 3245);
		DataInputStream din = new DataInputStream(ss.getInputStream());
		DataOutputStream dataoutput = new DataOutputStream(ss.getOutputStream());

		System.out.println("\n\nStarting AES Encryption/Decryption Algorithm");
		System.out.println("Encrypting : " + plaintext);
		System.out.println("Plaintext Length : " + plaintext.length());
// Initialing the time variables to calculate the time required for key generation 
		time1 = System.currentTimeMillis();
		time2 = time1;
		timing("Start");
		byte[] bkey;
		try {
			System.out.println("GENERATING SYMMETRIC KEY");
			KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
			keyGenerator.init(size);
			key = keyGenerator.generateKey();

		} catch (Exception e) {
			System.out.println(e);
		}

		System.out.println("Symmetric Key : " + new String(key.getEncoded()) + "\n");
		try {
			cipher = Cipher.getInstance("AES");
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		// The time values are subtracted here
		time2 = System.currentTimeMillis();
		timing("After Symetric Key Generation");
// Start of the symmetric encryption using the key generated above
		System.out.println("ENCRYPTION STARTED");
		time1 = System.currentTimeMillis();
		time2 = time1;
		timing("Start");
		try {
			cipher.init(Cipher.ENCRYPT_MODE, key);
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		try {
			encryptedBytes = cipher.doFinal(plaintext.getBytes());
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		time2 = System.currentTimeMillis();
		timing("After Encryption is completed using Symetric Key");
		System.out.println("THE ENCRYPTED MESSAGE IS\n " + new String(encryptedBytes));
		// Sending the encrypted message over the socket to the server
		dataoutput.writeInt(encryptedBytes.length);
		dataoutput.write(encryptedBytes);

		// sending key
		ByteBuffer bytebuffer = ByteBuffer.allocate(4);
		bytebuffer.putInt(key.getEncoded().length);
		ss.getOutputStream().write(bytebuffer.array());
		
		ss.getOutputStream().write(key.getEncoded());
		ss.getOutputStream().flush();
		System.out.println("\n\n............... FINISHED................ ");
		
	}
//Starting the Public Key Encryption
	public void rsaencyrption() throws UnknownHostException, IOException {

		System.out.println("\n\nStarting RSA Encryption/Decryption Algorithm");
		System.out.println("Encrypting : " + plaintext);
		System.out.println("Plaintext Length : " + plaintext.length());

		time1 = System.currentTimeMillis();
		time2 = time1;
		timing("Start");

		// keygeneration for Public Key using RSA protocol
		try {
			System.out.println("GENERATE PUBLIC and PRIVATE KEY");
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
			keyPairGenerator.initialize(2048);
			keyPair = keyPairGenerator.generateKeyPair();
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
	

		

			cipher = Cipher.getInstance("RSA");
			time2 = System.currentTimeMillis();
			timing("After generating keypair for Public Key based Encyption(RSA)");
		} catch (Exception e) {
			System.err.println("Error in initKeyPair()!\n " + e.getMessage() + "\n");
		}

		time1 = System.currentTimeMillis();
		time2 = time1;
		timing("Start");
		// Starting encryption using the key
		try {
			System.out.println("ENCRYPTION STARTED");
			cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPrivate());
			encryptedBytesaes = cipher.doFinal(plaintext.getBytes());
			System.out.println("THE ENCRYPTED MESSAGE IS\n " + new String(encryptedBytesaes));
		} catch (Exception e) {
			System.err.println("Error in encrypting! " + e.getMessage() + "!");
		}
		
		time2 = System.currentTimeMillis();
		timing("After Encryption is completed using a publik Key algorithm (RSA)");
		// Creating socket and establishing a connection with the server. Please note the change in the port number
		Socket ssaes = new Socket("localhost", 4567);
		//Initialzing stream objects to send data
		DataInputStream dinaes = new DataInputStream(ssaes.getInputStream());
		DataOutputStream dataoutputaes = new DataOutputStream(ssaes.getOutputStream());
		dataoutputaes.writeInt(encryptedBytesaes.length);
		dataoutputaes.write(encryptedBytesaes);

		// sending key
		keyBytes = keyPair.getPublic().getEncoded();
		dataoutputaes.writeInt(keyBytes.length);
		dataoutputaes.write(keyBytes);
		ssaes.getOutputStream().flush();
		
		System.out.println("\n\n............... FINISHED................ ");
	}
// Function for Digital Signature
	public void digitalsignature() {
		System.out.println("\n\nStarting Digital Signature");
		
		
		System.out.println("Message : " + plaintext);
		System.out.println("Message Length : " + plaintext.length());
		
		time1 = System.currentTimeMillis();
		time2 = time1;
		timing("Start");
		// Generating Key with the help of Key generator
		try {
			System.out.println("\n\nGENRATE PUBLIC and PRIVATE KEY");
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
			keyPairGenerator.initialize(2048);
			keyPairsignature = keyPairGenerator.generateKeyPair();
			// Initializing Signature 
			signature = Signature.getInstance("SHA512withRSA");

		} catch (Exception e) {
			System.err.println("Error in initKeyPair()! " + e.getMessage() + "!");
		}
		time2 = System.currentTimeMillis();
		timing("After Creating Signature");
		
		time1 = System.currentTimeMillis();
		time2 = time1;
		timing("Start");
		// Signing the plain text 
		try {

			signature.initSign(keyPairsignature.getPrivate());
			signature.update(plaintext.getBytes());
			sign = signature.sign();
			System.out.println("The message has been Signed using Digital Signature \n" + new String(sign));

			time2 = System.currentTimeMillis();
			timing("After Signing the message");

			// Creating socket and establishing a connection with the server. Please note the change in the port number
			Socket sssignature = new Socket("localhost", 4500);
			
			DataInputStream dinsign = new DataInputStream(sssignature.getInputStream());
			DataOutputStream dataoutputsign = new DataOutputStream(sssignature.getOutputStream());
			//Sending over the signed message 
			dataoutputsign.writeInt(sign.length);
			dataoutputsign.write(sign);
			System.out.println(sign);
			
			
			// send signature key
			keyBytessign = keyPairsignature.getPublic().getEncoded();
			dataoutputsign.writeInt(keyBytessign.length);
			dataoutputsign.write(keyBytessign);
			sssignature.getOutputStream().flush();
	

		} catch (Exception e) {
			System.err.println("Error in Digital Signature()! " + e.getMessage() + "!");
		}

		System.out.println("\n\n............... FINISHED................ ");
	}
// Function for Hash Function
	public void hashfunction() throws IOException, NoSuchAlgorithmException {
		System.out.println("\n\nStarting Hash Function");
		
		
		System.out.println("Message : " + plaintext);
		System.out.println("Message Length : " + plaintext.length());
		time1 = System.currentTimeMillis();
		time2 = time1;
		timing("Start");
		// Generating and storing md5 hash
		MessageDigest md = MessageDigest.getInstance("MD5");
		time2 = System.currentTimeMillis();
		timing("After Hash has been generated");
		// hashing the plain text
		md.update(plaintext.getBytes());
		byte[] hashed = md.digest();
		System.out.println("Message Hashed : " + new String(hashed));
		// Creating socket and establishing a connection with the server. Please note the change in the port number
		Socket sshash = new Socket("localhost", 3232);
		DataInputStream dinhash = new DataInputStream(sshash.getInputStream());
		DataOutputStream dataoutputhash = new DataOutputStream(sshash.getOutputStream());
		// Sending the hash
		dataoutputhash.writeInt(hashed.length);
		dataoutputhash.write(hashed);

		
		time2 = System.currentTimeMillis();
		timing("After Hashing has been completed over the plain text");

		System.out.println("\n\n............... FINISHED................ ");
	}
// TIming function to calculate time intervals
	private static void timing(String header) {

		System.out.println("\nMemory available at " + header + " (Free/Total): ( " + Runtime.getRuntime().freeMemory()
				+ " / " + Runtime.getRuntime().totalMemory() + " )");

		System.out.println("Time at " + header + ": " + (time2 - time1) + "\n");

	}

}
