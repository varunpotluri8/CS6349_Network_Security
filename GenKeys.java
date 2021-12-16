import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;


public class GenKeys 
{
	static String keypath = "C:\\Users\\Varun\\Desktop\\FileTransferUTD\\Keys";
	
	public static void main(String[] args) throws CertificateException 
    {
            try 
            {
                KeyPairGenerator keyPairGenerator=KeyPairGenerator.getInstance("RSA");
                keyPairGenerator.initialize(3072);
                KeyPair keyPair=keyPairGenerator.generateKeyPair();
                PublicKey publicKey=keyPair.getPublic();
                PrivateKey privateKey=keyPair.getPrivate();
                writeKeys(keypath + "ClientPubKey.txt",publicKey.getEncoded());
                writeKeys(keypath + "ClientPrivKey.txt",privateKey.getEncoded());
                System.out.println("Client Keys generated successfully");
            } 
            catch (NoSuchAlgorithmException | IOException ex) 
            {
                ex.printStackTrace();
            }
            
            try 
            {
                KeyPairGenerator keyPairGenerator=KeyPairGenerator.getInstance("RSA");
                keyPairGenerator.initialize(3072);
                KeyPair keyPair=keyPairGenerator.generateKeyPair();
                PublicKey publicKey=keyPair.getPublic();
                PrivateKey privateKey=keyPair.getPrivate();
                writeKeys(keypath + "ServerPubKey.txt",publicKey.getEncoded());
                writeKeys(keypath + "ServerPrivKey.txt",privateKey.getEncoded());
                System.out.println("Server Keys generated successfully");	
            } 
            catch (NoSuchAlgorithmException | IOException ex) 
            {
                ex.printStackTrace();
            }
	}

	
    public static void writeKeys(String fileName,byte[] b) throws FileNotFoundException, IOException
    {
        FileOutputStream fos = new FileOutputStream(new File(fileName));
		fos.write(b);
		fos.flush();
		fos.close();
    }
}