import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.ServerSocket;
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

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class Server 
{
	//static String filepath = "C:\\Users\\juhip\\eclipse-workspace\\File Tranfer\\src\\Server Files\\";
	//static String keypath = "C:\\Users\\juhip\\eclipse-workspace\\File Tranfer\\src\\Keys\\";
	static String filepath = "C:\\Users\\Varun\\Desktop\\FileTransferUTD\\Server Files";
	static String keypath = "C:\\Users\\Varun\\Desktop\\FileTransferUTD\\Keys";
	
	static byte[] ClientPublicKey;
	static byte[] ServerPublicKey;
	static byte[] ServerPrivateKey;
	static PublicKey CPublicKey;
	static PublicKey SPublicKey;
	static PrivateKey SPrivateKey;
	static byte[] SessionKey;
	
	public static void main(String[] args) throws IOException, InvalidKeySpecException, NoSuchAlgorithmException, CertificateException
	{
		ServerSocket serverSock = null;
	
		try 
		{
			//serverSock = new ServerSocket(1234); //create socket on the node's port
			serverSock = new ServerSocket(5454);
		} 
		catch (IOException e) 
		{
			e.printStackTrace();
		}
		
		Socket sock = serverSock.accept();
		DataInputStream in =  new DataInputStream(sock.getInputStream());
		DataOutputStream out = new DataOutputStream(sock.getOutputStream());
		
		
		ValidateServer(in, out);
		ExchangeKeys(in, out);
		
		ServerAction(in, out);
		serverSock.close();
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
        for(int i = 0; i < ServerPrivateKey.length; i++)
        {
            pr += (int)ServerPrivateKey[i];
        }
        pr = Math.abs(pr);
        //System.out.println(pr);
        
        // calculate Public Value B
        int B =power(g,pr,p);
        //System.out.println(B);

        // Wait until A is received from client
        int A= in.readInt();
        // Send B to client
        out.writeInt(B);
        //System.out.println("Session Key Exchange");
        out.flush();

        // Calculate X
        int DiffieKey =power(A,pr,p);
        //System.out.println(DiffieKey);
        SessionKey = BigInteger.valueOf(DiffieKey).toByteArray();
	}
	
	public static int power(int a, int b, int p)
    {
        if (b == 1)
            return a;
        else
            return (((int)Math.pow(a, b)) % p);
    }
	
	public static void ValidateServer(DataInputStream in, DataOutputStream out) throws IOException, InvalidKeySpecException, NoSuchAlgorithmException, CertificateException
	{
		File serverpubkey = new File(keypath + "ServerPubKey.txt");
		File serverprivkey = new File(keypath + "ServerPrivKey.txt");
		File servercert = new File(keypath + "servercert.crt");
		
		if(!serverpubkey.exists())
		{
			System.out.println("Server public key not found");
		}
		
		if(!serverprivkey.exists())
		{
			System.out.println("Server private key not found");
		}
		
		ServerPublicKey = Files.readAllBytes(serverpubkey.toPath());
		ServerPrivateKey = Files.readAllBytes(serverprivkey.toPath());
		
		X509EncodedKeySpec ServerPublicKeyencoded = new X509EncodedKeySpec(ServerPublicKey);
		PKCS8EncodedKeySpec ServerPrivateKeyencoded = new PKCS8EncodedKeySpec(ServerPrivateKey);
		
		KeyFactory spubkf = KeyFactory.getInstance("RSA");
		KeyFactory sprivkf = KeyFactory.getInstance("RSA");
		
		SPublicKey = spubkf.generatePublic(ServerPublicKeyencoded);
		SPrivateKey = sprivkf.generatePrivate(ServerPrivateKeyencoded);
		
		int keylength = in.readInt();
		byte[] readclientkey = new byte[keylength];
		in.readFully(readclientkey, 0, keylength);
		ClientPublicKey = readclientkey;
		
		X509EncodedKeySpec ClientPublicKeyencoded = new X509EncodedKeySpec(ClientPublicKey);
		KeyFactory cpubkf = KeyFactory.getInstance("RSA");
		CPublicKey = cpubkf.generatePublic(ClientPublicKeyencoded);
		
		CertificateFactory fac = CertificateFactory.getInstance("X509");
		FileInputStream is = new FileInputStream(servercert.getAbsolutePath());
		X509Certificate cert = (X509Certificate) fac.generateCertificate(is);
		byte[] certif = cert.getEncoded();
		out.writeInt(certif.length);
		out.write(certif);
		
		out.writeInt(ServerPublicKey.length);
		out.write(ServerPublicKey);	

		
		//////////////////////////////////////////////////////////////////////
		int validatelength = in.readInt();
		byte[] decodevalidate = new byte[validatelength];
		in.readFully(decodevalidate, 0, validatelength);
		
		try 
		{
			byte[] validate = decode(decodevalidate);
			byte[] encodedvalidate = encode(validate);
			out.writeInt(encodedvalidate.length);
			out.write(encodedvalidate);
		} 
		catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException | NoSuchAlgorithmException| NoSuchPaddingException | InvalidKeySpecException e) 
		{
			e.printStackTrace();
		}
		////////////////////////////////////////////////////////////////////////
	}
	
	public static byte[] encode(byte[] toencode) throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException
	{
		Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, CPublicKey);
        byte[] encryptedBytes = cipher.doFinal(toencode);
	
		return encryptedBytes;
	}
	
	public static byte[] decode(byte[] todecode) throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException
	{
		Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, SPrivateKey);

        byte[] decryptedBytes = cipher.doFinal(todecode);

        return decryptedBytes;
	}
	
	public static void ServerAction(DataInputStream in, DataOutputStream out) throws IOException, NoSuchAlgorithmException
	{
		FileOutputStream fos = null;
		FileInputStream finput = null;
		
		while(true)
		{
			String msg = in.readUTF(); //Get the action to perform
			//System.out.println(msg);
			
			if(msg.equalsIgnoreCase("upload"))
			{
				//System.out.println("upload");
				
				//Get name of file being uploaded
				String filename = in.readUTF(); 
				//System.out.println(filename);
						
				//Get the bytes of the file being downloaded
				int filelength = in.readInt();
				byte[] uploadedfileencoded = new byte[filelength];
				in.readFully(uploadedfileencoded, 0, uploadedfileencoded.length);

				///////////////
				//DECODE FILE//
				///////////////
				byte[] uploadedfileencodednohash = Arrays.copyOfRange(uploadedfileencoded, 0, filelength - 32);
				byte[] hashfromfile = Arrays.copyOfRange(uploadedfileencoded, filelength - 32, filelength);
				
				byte[] tempkey = generateKey(uploadedfileencodednohash.length);
				byte[] uploadedfile = Ciphertext(tempkey, uploadedfileencodednohash);
				
				
				MessageDigest digest = MessageDigest.getInstance("SHA-256");
				byte[] hash = digest.digest(uploadedfile);
				
				
				if(Arrays.equals(hash, hashfromfile))
				{
					//Create file from file bytes
					fos = new FileOutputStream(filepath + filename);
					fos.write(uploadedfile);
					fos.close();
					out.writeUTF("SECURE");
				}
				else 
				{
					out.writeUTF("INSECURE");
				}
			}
			else if(msg.equalsIgnoreCase("download"))
			{
				//System.out.println("download");
				
				//Write list of files able to be downloaded in directory currently
				File directory = new File(filepath);
				String files[] = directory.list();
				out.writeInt(files.length);
				for(String file : files)
				{
					out.writeUTF(file);
				}
				
				//Choose file to be downloaded
				String dfile = in.readUTF();
				File f = new File(filepath + dfile);
				finput = new FileInputStream(f.getAbsolutePath());
				//System.out.println(f.getName());
			
				//Send file to client
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
			}
			else if(msg.equalsIgnoreCase("logout"))
			{
				//System.out.println("Exit");
				break;
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
}
