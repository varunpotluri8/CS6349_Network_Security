import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.Socket;
import java.nio.file.Files;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Random;
import java.util.Scanner;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class Client 
{
	//static String filepath = "C:\\Users\\juhip\\eclipse-workspace\\File Tranfer\\src\\Client Files\\";
	//static String keypath = "C:\\Users\\juhip\\eclipse-workspace\\File Tranfer\\src\\Keys\\";
	static String filepath = "C:\\Users\\Varun\\Desktop\\FileTransferUTD\\Client Files";
	static String keypath = "C:\\Users\\Varun\\Desktop\\FileTransferUTD\\Keys";
	
	static byte[] ClientPublicKey;
	static byte[] ClientPrivateKey;
	static byte[] ServerPublicKey;
	static PublicKey CPublicKey;
	static PublicKey SPublicKey;
	static PrivateKey CPrivateKey;
	static byte[] SessionKey;
	
	public static void main(String[] args) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, CertificateException
	{
		Socket socket = null;
		DataOutputStream out;
		DataInputStream in;
		Scanner getin = new Scanner(System.in);
			
		try 
		{
			//socket = new Socket("localhost", 1234);
			
			socket = new Socket("net01.utdallas.edu", 5454); //create new socket
			
			in =  new DataInputStream(socket.getInputStream());
			out = new DataOutputStream(socket.getOutputStream());
			
			///////////////////
			//VALIDATE SERVER//
			///////////////////
			Welcome();
			ValidateServer(in, out);
			ExchangeKeys(in, out);
			UserAction("", in, out, getin);
			
		} 
		catch (IOException e) 
		{
			e.printStackTrace();
		}
		getin.close();
		socket.close();
		System.exit(0);
	}
	
	public static void ExchangeKeys(DataInputStream in, DataOutputStream out) throws IOException
	{
		int g = 0;
        for(int i = 0; i < ClientPublicKey.length; i++)
        {
            g += (int)ClientPublicKey[i];
        }
        g = Math.abs(g);
        //System.out.println(g);
        
        int p = 0;
        for(int i = 0; i < ServerPublicKey.length; i++)
        {
            p += (int)ServerPublicKey[i];
        }
        p = Math.abs(p);
        //System.out.println(p);
        
        int pr=0;
        for(int i = 0; i < ClientPrivateKey.length; i++)
        {
            pr += (int)ClientPrivateKey[i];
        }
        pr = Math.abs(pr);
        //System.out.println(pr);
          
        // calculate Public Value A
        int A =power(g,pr,p);
        //System.out.println(A);

        // Send A to server
        out.writeInt(A);
        out.flush();
        
        // Wait until B is received from server
        int B = in.readInt();
        System.out.println("Session Key Exchanged\n");
        
        // calculate X
        int DiffieKey = power(B,pr,p);
        SessionKey = BigInteger.valueOf(DiffieKey).toByteArray();
	}
	
	public static int power(int a, int b, int p)
    {
        if (b == 1)
            return a;
        else
            return (((int)Math.pow(a, b)) % p);
    }
	
	public static void ValidateServer(DataInputStream in, DataOutputStream out) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, CertificateException
	{		
		System.out.println("VALIDATING SERVER CONNECTION...");
		
		File clientpubkey = new File(keypath + "ClientPubKey.txt");
		File clientprivkey = new File(keypath + "ClientPrivKey.txt");
		
		if(!clientpubkey.exists())
		{
			System.out.println("Client public key not found");
		}
		
		if(!clientprivkey.exists())
		{
			System.out.println("Client private key not found");
		}
		
		ClientPublicKey = Files.readAllBytes(clientpubkey.toPath());
		ClientPrivateKey = Files.readAllBytes(clientprivkey.toPath());
				
		X509EncodedKeySpec ClientPublicKeyencoded = new X509EncodedKeySpec(ClientPublicKey);
		PKCS8EncodedKeySpec ClientPrivateKeyencoded = new PKCS8EncodedKeySpec(ClientPrivateKey);
		
		KeyFactory cpubkf = KeyFactory.getInstance("RSA");
		KeyFactory cprivkf = KeyFactory.getInstance("RSA");
		
		CPublicKey = cpubkf.generatePublic(ClientPublicKeyencoded);
		CPrivateKey = cprivkf.generatePrivate(ClientPrivateKeyencoded);
		
		System.out.println("Sending client public key to server and requesting connection...");
		
		out.writeInt(ClientPublicKey.length);
		out.write(ClientPublicKey);	
		
		System.out.println("Reading server certificate...");
		int certlength = in.readInt();
		byte[] certif = new byte[certlength];
		in.readFully(certif, 0, certlength);
		CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
		InputStream certin = new ByteArrayInputStream(certif);
		X509Certificate certificate = (X509Certificate)certFactory.generateCertificate(certin);
		SPublicKey = certificate.getPublicKey();
		
		//Convert server public key to bytes
		int keylength = in.readInt();
		byte[] readserverkey = new byte[keylength];
		in.readFully(readserverkey, 0, keylength);
		ServerPublicKey = readserverkey;

		//Send validation token to server
		X509EncodedKeySpec ServerPublicKeyencoded = new X509EncodedKeySpec(ServerPublicKey);
		KeyFactory spubkf = KeyFactory.getInstance("RSA");
		SPublicKey = spubkf.generatePublic(ServerPublicKeyencoded);
		Random rand = new Random();
		byte[] validate = new byte[20];
		rand.nextBytes(validate);
		System.out.println("Sending validation token...");
		try 
		{
			byte[] encodedvalidate = encode(validate);
			out.writeInt(encodedvalidate.length);
			out.write(encodedvalidate);	
			
			int validatelength = in.readInt();
			byte[] servervalidate = new byte[validatelength];
			in.readFully(servervalidate, 0, validatelength);
			
			byte[] decodedvalidate = decode(servervalidate);
			
			if(Arrays.equals(validate, decodedvalidate))
			{
				System.out.println("Validation Success!");
				return;
			}
			else
			{
				System.out.println("Server did not pass validation. Exiting Service");
				System.exit(-1);
			}
		} 
		catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException | InvalidKeySpecException| NoSuchAlgorithmException | NoSuchPaddingException e)
		{
			e.printStackTrace();
		}
	}
	
	public static byte[] encode(byte[] toencode) throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException
	{
		Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, SPublicKey);
        byte[] encryptedBytes = cipher.doFinal(toencode);
	
		return encryptedBytes;
	}
	
	public static byte[] decode(byte[] todecode) throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException
	{
		Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, CPrivateKey);

        byte[] decryptedBytes = cipher.doFinal(todecode);

        return decryptedBytes;
	}
	
	public static void UserAction(String action, DataInputStream in, DataOutputStream out, Scanner getin) throws IOException, NoSuchAlgorithmException
	{
		FileOutputStream fos = null;
		FileInputStream finput = null;
		Boolean exitFlag = false;
		
		while(!exitFlag) //loop until user logs out
		{
			//Get the user action
			action = Menu();
			
			if(action.equalsIgnoreCase("1") || action.equalsIgnoreCase("upload"))
			{
				//Get the file to be uploaded
				File directory = new File(filepath);
				String files[] = directory.list();
				printFiles(files);				
				String input = getFile(files, getin);		
					
				out.writeUTF("UPLOAD");
				
				//Write the file name to the server
				File f = new File(filepath + input);
				//System.out.println(f.getName());
				out.writeUTF(f.getName());
				
				//Write the bytes of the file to the server
				finput = new FileInputStream(f.getAbsolutePath());
				byte[] fileBytes = new byte[(int)f.length()];				
				finput.read(fileBytes);
				
				///////////////
				//ENCODE FILE//
				///////////////
					
				byte[] tempkey = generateKey(fileBytes.length);
				byte[] encodedfile = Ciphertext(tempkey, fileBytes);
				MessageDigest digest = MessageDigest.getInstance("SHA-256");
                byte[] hash = digest.digest(fileBytes);
				
                byte[] ciphertextfinal = new byte[fileBytes.length + 32];
                System.arraycopy(encodedfile, 0, ciphertextfinal, 0, fileBytes.length);
                System.arraycopy(hash, 0, ciphertextfinal, fileBytes.length, 32);
                
				out.writeInt(ciphertextfinal.length);
				out.write(ciphertextfinal);
				
				String msg = in.readUTF();
				if(msg.equalsIgnoreCase("INSECURE"))
				{
					System.out.println("The file was tampered with according to the server. It was not uploaded.");
				}
				else
				{
					System.out.println("Upload success!");
				}
				
				System.out.println("");
			}
			else if(action.equalsIgnoreCase("2") || action.equalsIgnoreCase("download"))
			{		
				out.writeUTF("DOWNLOAD");
				
				//Get the file to be downloaded
				int numfiles = in.readInt();
				String [] files = new String[numfiles];
				for(int i = 0; i < numfiles; i++)
				{
					files[i] = in.readUTF();
				}
				printFiles(files);
				String input = getFile(files, getin);
				out.writeUTF(input);
				String filename = input;
				//System.out.println(filename);
				
				//Get the bytes of the file being downloaded
				int filelength = in.readInt();
				byte[] downloadedfileencoded = new byte[filelength];
				in.readFully(downloadedfileencoded, 0, downloadedfileencoded.length);

				///////////////
				//DECODE FILE//
				///////////////
				
				byte[] downloadedfileencodednohash = Arrays.copyOfRange(downloadedfileencoded, 0, filelength - 32);
				byte[] hashfromfile = Arrays.copyOfRange(downloadedfileencoded, filelength - 32, filelength);
				
				byte[] tempkey = generateKey(downloadedfileencodednohash.length);
				byte[] downloadedfile = Ciphertext(tempkey, downloadedfileencodednohash);
				
				
				MessageDigest digest = MessageDigest.getInstance("SHA-256");
				byte[] hash = digest.digest(downloadedfile);
				
				
				if(Arrays.equals(hash, hashfromfile))
				{
					//Create file from file bytes
					fos = new FileOutputStream(filepath + filename);
					fos.write(downloadedfile);
					fos.close();
					System.out.println("Download Success");
				}
				else 
				{
					System.out.println("File has been tampered with.");
				}
				
				System.out.println("");
			}
			else if(action.equalsIgnoreCase("3") || action.equalsIgnoreCase("logout"))
			{
				exitFlag = true;
				System.out.println("Goodbye!");
				out.writeUTF("LOGOUT");
			}
		}
	}
	
	public static byte[] Ciphertext(byte[] key, byte[] file)
	{
		byte[] ciphertext = new byte[file.length];
        for(int i = 0; i < file.length; i++)
        {
            ciphertext[i] = (byte) (file[i] ^ key[i]);
        }
        
        return ciphertext;
	}
	
	public static byte[] generateKey(int filesize)
	{
		byte[] tempKey = new byte[filesize];
		
        for(int i = 0; i < tempKey.length; i++)
        {
            tempKey[i] = SessionKey[i % SessionKey.length];
        }
        
        return tempKey;
	}
	
	public static void printFiles(String[] files)
	{
		System.out.println("Files: ");
		for(String f : files)
		{
			System.out.print("-->");
			System.out.println(f);
		}
	}
	
	public static String getFile(String[] files, Scanner getin)
	{
		String input = "";		
		
		while(!Contains(files, input))
		{
			System.out.print("Please choose a file: ");
			input = getin.nextLine();
			if(!Contains(files, input))
			{
				System.out.println("This file does not exist.");
			}
		}
		
		return input;
	}
	
	public static Boolean Contains(String[] list, String l)
	{
		for(String x : list)
		{
			if(x.equalsIgnoreCase(l))
			{
				return true;
			}
		}
		return false;
	}
	
	public static String Menu()
	{
		@SuppressWarnings("resource")
		Scanner getin = new Scanner(System.in);	
		String input = null;
		while(true)
		{
			System.out.println("Would you like to:");
			System.out.println("1. Upload");
			System.out.println("2. Download");
			System.out.println("3. Logout");
			System.out.print("Your Choice: ");
			input = getin.nextLine();
			if(input.equalsIgnoreCase("1") || input.equalsIgnoreCase("upload") 
			|| input.equalsIgnoreCase("2") || input.equalsIgnoreCase("download")
			|| input.equalsIgnoreCase("3") || input.equalsIgnoreCase("logout"))
			{
				break;
			}
			else
			{
				System.out.println("Invalid input. Please select one of the three choices");
			}
		}
		System.out.println("");
		return input;
	}
	
	public static void Welcome()
	{
		System.out.println(" ______   ______     ______     ______     __         ______        _____     ______     __     __   __   ______    \r\n"
				+ "/\\  ___\\ /\\  __ \\   /\\  __ \\   /\\  ___\\   /\\ \\       /\\  ___\\      /\\  __-.  /\\  == \\   /\\ \\   /\\ \\ / /  /\\  ___\\   \r\n"
				+ "\\ \\  __\\ \\ \\ \\/\\ \\  \\ \\ \\/\\ \\  \\ \\ \\__ \\  \\ \\ \\____  \\ \\  __\\      \\ \\ \\/\\ \\ \\ \\  __<   \\ \\ \\  \\ \\ \\'/   \\ \\  __\\   \r\n"
				+ " \\ \\_\\    \\ \\_____\\  \\ \\_____\\  \\ \\_____\\  \\ \\_____\\  \\ \\_____\\     \\ \\____-  \\ \\_\\ \\_\\  \\ \\_\\  \\ \\__|    \\ \\_____\\ \r\n"
				+ "  \\/_/     \\/_____/   \\/_____/   \\/_____/   \\/_____/   \\/_____/      \\/____/   \\/_/ /_/   \\/_/   \\/_/      \\/_____/ \r\n"
				+ "                                                                                                                    ");
		
		System.out.println("Welcome to Foogle Drive, a Cloud file storage system!");
		System.out.println("Please wait while we authenticate the server...\n");
	}
}
