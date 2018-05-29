/**
 * 
 */


import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Scanner;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * @author Sunit Tiwari
 *
 */
public class Server {
//Declaring all the variables as public to avoid any scope issues
	static Cipher cipher;
	static byte[] decryptedBytes;
	private static Signature signature;
	private static byte[] encryptedBytesServer = null;
	private static String plaintext = null;
	public static long time1 = 0;
	public static long time2 = 0;
	public static void main(String[] args)
			throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
			IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException, SignatureException {
		System.out.println("Server is Running awaiting Client connection");
		
		// Getting plain text from the client
		
		ServerSocket serversocketplaintext = new ServerSocket(4545);
		Socket splaintext = serversocketplaintext.accept();
		Scanner scgetplain = new Scanner(splaintext.getInputStream());
		plaintext = scgetplain.nextLine();
		System.out.println("Plain text recieved over the socket is :-"+plaintext);
		
		// AES Decryption
		
		ServerSocket serversocket = new ServerSocket(3245);
		Socket s = serversocket.accept();
		System.out.println("\n\nStarting AES Decryption Algorithm on the Server");
		DataInputStream dIn = new DataInputStream(s.getInputStream());
		Key Key = null;

		int length = dIn.readInt(); // read length of incoming message
		if (length > 0) {
			byte[] message = new byte[length];
			dIn.readFully(message, 0, message.length); // read the message
			System.out.println(new String(message));

			// get key for AES
			byte[] lenb = new byte[4];
			s.getInputStream().read(lenb, 0, 4);
			ByteBuffer br = ByteBuffer.wrap(lenb);
			int len = br.getInt();
			byte[] aesKeyBytes = new byte[len];
			s.getInputStream().read(aesKeyBytes);
			Key = new SecretKeySpec(aesKeyBytes, 0, aesKeyBytes.length, "AES");
			cipher = Cipher.getInstance("AES");
		
			
			time1 = System.currentTimeMillis();
			time2 = time1; 
	    	timing("Before Decryption is Starting");
			// Decryption is starting
	    	System.out.println("DECRYPTION STARTED");
			cipher.init(Cipher.DECRYPT_MODE, Key);
			decryptedBytes = cipher.doFinal(message);
			System.out.println("THE DECRYPTED MESSAGE IS\n " + new String(decryptedBytes));
			time2 = System.currentTimeMillis();
	    	timing("After Decrypt");
		}

		// RSA DECRYPTION
		
		System.out.println("\n\n Starting Public key Based Algorithm (RSA)Decryption on the Server");

		ServerSocket serversocketrsa = new ServerSocket(4567);
		
		Socket srsa = serversocketrsa.accept();
	
		DataInputStream dInrsa = new DataInputStream(srsa.getInputStream());
		KeyPair keypair = null;
		int lengthrsa = dInrsa.readInt();
		time1 = System.currentTimeMillis();
		time2 = time1; 
		timing("Before Decryption is Starting");
		
		// read length of incoming message
		if (lengthrsa > 0) {
			byte[] messagersa = new byte[lengthrsa];
			dInrsa.readFully(messagersa, 0, messagersa.length); // read the message
			System.out.println(new String(messagersa));

			// get key for RSA
			
			byte[] keybytes = new byte[dInrsa.readInt()];
			dInrsa.readFully(keybytes);
			// Making sure that the format of the key remains intact after receiving it as bytes 
			//and then converting it back to the key datatype format 
			KeyFactory kf = KeyFactory.getInstance("RSA");
			X509EncodedKeySpec x5encodedkeysepc = new X509EncodedKeySpec(keybytes);
			PublicKey privatekey = kf.generatePublic(x5encodedkeysepc);
		
	
			
			
			cipher = Cipher.getInstance("RSA");
		// Decryption Started for RSA
			System.out.println("DECRYPTION STARTED RSA");
			cipher.init(Cipher.DECRYPT_MODE, privatekey);
			decryptedBytes = cipher.doFinal(messagersa);
			System.out.println("THE DECRYPTED MESSAGE IS\n " + new String(decryptedBytes));
			time2 = System.currentTimeMillis();
	    	timing("After Decryption of RSA");
		}
		
		// Signature Verification:-

		
		System.out.println("\n\nStarting verification of Signature on the Server Side");
// Receiving the incoming connection
		ServerSocket serversocketsignature = new ServerSocket(4500);
		Socket ssignature = serversocketsignature.accept();
		
		DataInputStream dInsign = new DataInputStream(ssignature.getInputStream());
		KeyPair keyPairsignature;
		
		
		int lengthsign = dInsign.readInt();
		// Getting the signed message
		if (lengthsign > 0) {
			byte[] messagesign = new byte[lengthsign];
			dInsign.readFully(messagesign, 0, messagesign.length); // read the message
			System.out.println(new String(messagesign));

			time1 = System.currentTimeMillis();
			time2 = time1; 
			timing("Before Signature verification");
			
			// Get PublicKey for Digital Signature :-
			byte[] keybytesign = new byte[dInsign.readInt()];
			dInsign.readFully(keybytesign);
			KeyFactory kfsign = KeyFactory.getInstance("RSA");
			X509EncodedKeySpec x5encodedkeysepcsign = new X509EncodedKeySpec(keybytesign);
			PublicKey privatekeysign = kfsign.generatePublic(x5encodedkeysepcsign);
	// Verifying it 
			signature = Signature.getInstance("SHA512withRSA");
			signature.initVerify(privatekeysign);
			signature.update(plaintext.getBytes());
			boolean verifies = signature.verify(messagesign);
			System.out.println("\nVerify -- " + verifies + " --");
			time2 = System.currentTimeMillis();
	        timing("After Signature is verified !!");

		}
		// Hash Function
		
		MessageDigest md = MessageDigest.getInstance("MD5");
		md.update(plaintext.getBytes());
		byte[] hashedonserver = md.digest();
		System.out.println(new String(hashedonserver));
		
		// Get the hash value from the client
		
		System.out.println("\n\nStarting Hashing on the Server Side");
		ServerSocket serversockethashing = new ServerSocket(3232);
		Socket hashing = serversockethashing.accept();
		DataInputStream dInhash = new DataInputStream(hashing.getInputStream());
		time1 = System.currentTimeMillis();
		time2 = time1; 
    	timing("At the start of the Hashing");
		
		byte[] messagehash = new byte[dInhash.readInt()];
		dInhash.readFully(messagehash);
		System.out.println(new String(messagehash));
        
		// Comparing both the hashes
		if (Arrays.equals(messagehash, hashedonserver)) {
			System.out.println("Hashes are equal.!!! ");
		}
		else
			System.out.println("Hashes are not equal");

		time2 = System.currentTimeMillis();
	    timing("After Hashes are Compared !!");
	}
	 
	// To calculate time interval on the server side
	private static void timing(String header) {

		System.out.println("\nMemory available at " + header + " (Free/Total): ( " + Runtime.getRuntime().freeMemory()
				+ " / " + Runtime.getRuntime().totalMemory() + " )");

		System.out.println("Time at " + header + ": " + (time2 - time1) + "\n");

	}
}
