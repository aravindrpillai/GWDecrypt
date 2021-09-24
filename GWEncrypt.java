import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.charset.Charset;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Base64;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class GWDecrypt {

	  private static final String ALGORITHM = "AES";
	  private static final String ALGORITHM_MODE_PADDING = ALGORITHM + "/CBC/PKCS5Padding";
	  private static final String IV = "d0b1b71f5f557d19";
	  private static String keyAlias = "entityEncryption";
	  public static String KeystoreLocation;

	  private static final Charset CHARSET = Charset.forName("UTF-8");
	  private SecretKeySpec _keySpec = null;
	  private Cipher _cipher = null;
	  private IvParameterSpec _ivSpec = null;

	  GWDecrypt(){}

	  private void initialize(String key) throws NoSuchAlgorithmException, NoSuchPaddingException {
	    if (key == null) {
	      throw new NullPointerException();
	    }
	    initCipher();
	    _ivSpec = new IvParameterSpec(IV.getBytes(CHARSET));
	    _keySpec = new SecretKeySpec(Base64.getDecoder().decode(key), ALGORITHM);
	  }



	  private void initCipher() throws NoSuchPaddingException, NoSuchAlgorithmException {
	    _cipher = Cipher.getInstance(ALGORITHM_MODE_PADDING);
	  }

	  public String encryptValue(String plainText) throws InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
	    if (_cipher == null) {
	      throw new IllegalStateException("CryptoImpl has not been initialized");
	    }
	    String cipherText = null;
	    if (plainText != null) {
	      _cipher.init(Cipher.ENCRYPT_MODE, _keySpec, _ivSpec);
	      byte[] encrypted = _cipher.doFinal(plainText.getBytes(CHARSET));
	      cipherText = Base64.getEncoder().encodeToString(encrypted);
	    }
	    return cipherText;
	  }


	  public String decryptValue(String base64EncodedEncryptedText) throws InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
	    if (_cipher == null) {
	      throw new IllegalStateException("CryptoImpl has not been initialized");
	    }
	    String clearText = null;
	    if (base64EncodedEncryptedText != null) {
	      byte[] encryptedBytes = Base64.getDecoder().decode(base64EncodedEncryptedText);
	      byte[] decryptedBytes;
	      _cipher.init(Cipher.DECRYPT_MODE, _keySpec, _ivSpec);
	      decryptedBytes = _cipher.doFinal(encryptedBytes);
	      clearText = new String(decryptedBytes, CHARSET);
	    }
	    return clearText;
	  }

	  static final class KeystoreAccess {

	    static final String KEYSTORE_TYPE = "JCEKS";
	    static byte[] readKeyFromStore(String keystoreLocation , char[] keystorePassword, String keyAlias ,char[] keyPassword) throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException {
	      KeyStore keystore = KeyStore.getInstance(KEYSTORE_TYPE);
	      java.io.File file = new java.io.File(keystoreLocation);
	      keystore.load(new BufferedInputStream(new FileInputStream(file)),keystorePassword);
	      if (!keystore.containsAlias(keyAlias)) {
	        throw new IllegalArgumentException( "No such key ${keyAlias} found in keystore at ${keystoreLocation}");
	      }

	      return keystore.getKey(keyAlias, keyPassword).getEncoded();
	    }
	  }



	  private String readKey() throws IOException, UnrecoverableKeyException, CertificateException, NoSuchAlgorithmException, KeyStoreException {
	    if (KeystoreLocation != null) {
	      char[] keystorePassword = ("gw").toCharArray();
	      char[] keyPassword = ("gw").toCharArray();
	      byte[] keyBytes = KeystoreAccess.readKeyFromStore(KeystoreLocation, keystorePassword, keyAlias, keyPassword);
	      return Base64.getEncoder().encodeToString(keyBytes);
	    }  else {
	      return null;
	    }
	  }


	  public static GWDecrypt Initilize() {
		GWDecrypt _cryptoAPI = new GWDecrypt();
	    String key = null;
	    try {
	      key = _cryptoAPI.readKey();
	    } catch (Exception e) {
	      e.printStackTrace();
	    }
	    if (key != null) {
	      try {
	        _cryptoAPI.initialize(key);
	      } catch (Exception e) {
	        e.printStackTrace();
	      }
	    }
	    return _cryptoAPI;
	  }



	  public static void main(String[] args){
		System.out.println("Starting...!!");
	    StringBuilder output = new StringBuilder();
	    try {
	    	final String dir = System.getProperty("user.dir");
	        System.out.println("current dir = " + dir);
	    	
		    String ksLocation = dir+"/entity-encryption.jks";
		    String inputLocation = dir+"/input.txt";
		    String outputLocation = dir+"/output.txt";

	    	System.out.println("Key Location : "+ksLocation);
	    	System.out.println("Input Location : "+inputLocation);
	    	System.out.println("Output Location : "+outputLocation);

	    	
	    	KeystoreLocation = ksLocation;
	    	GWDecrypt obj = Initilize();
	    	File file = new File(inputLocation);
	    	BufferedReader br = new BufferedReader(new FileReader(file));
	    	String line;
    	    while ((line = br.readLine()) != null) {
    	    	output.append(line.split("~")[0]);
    	    	output.append("~".concat(obj.decryptValue(line.split("~")[1])));
    	    	output.append("\n");
    	    }
    	    new FileOutputStream(outputLocation, false).close();
    	    BufferedWriter writer = new BufferedWriter(new FileWriter(new File(outputLocation)));
            writer.write(output.toString());
            writer.close();
	    } catch (Exception e) {
	      e.printStackTrace();
	    }
	    System.out.println("Done");
	  }

}
