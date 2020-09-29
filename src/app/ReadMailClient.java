package app;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
// Sertifikat ce biti potreban pri validaciji potpisa
//import java.security.cert.Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.mail.MessagingException;
import javax.mail.internet.MimeMessage;

//import org.apache.xml.security.utils.JavaUtils;

import com.google.api.services.gmail.Gmail;
import com.google.api.services.gmail.model.Message;

import keystore.KeyStoreReader;
import model.mailclient.MailBody;
import support.MailHelper;
import support.MailReader;
import util.Base64;
import util.GzipUtil;

public class ReadMailClient extends MailClient {

	public static long PAGE_SIZE = 3;
	public static boolean ONLY_FIRST_PAGE = true;
	
	//private static final String KEY_FILE = "./data/session.key";
	//private static final String IV1_FILE = "./data/iv1.bin";
	//private static final String IV2_FILE = "./data/iv2.bin";
	
	private static final String USERB_KS = "./data/userb.jks";
	private static final String USERB_KS_PASS = "1234";
	private static final String USERB_KS_ALIAS = "userb";
	private static final String USERB_KS_PASS_FOR_ALIAS = "1234";
	
	private static KeyStoreReader keyStoreReader = new KeyStoreReader();
	
	
	public static void main(String[] args) throws IOException, InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException, MessagingException, NoSuchPaddingException, InvalidAlgorithmParameterException {
        // Build a new authorized API client service.
        Gmail service = getGmailService();
        ArrayList<MimeMessage> mimeMessages = new ArrayList<MimeMessage>();
        
        String user = "me";
        String query = "is:unread label:INBOX";
        
        List<Message> messages = MailReader.listMessagesMatchingQuery(service, user, query, PAGE_SIZE, ONLY_FIRST_PAGE);
        for(int i=0; i<messages.size(); i++) {
        	Message fullM = MailReader.getMessage(service, user, messages.get(i).getId());
        	
        	MimeMessage mimeMessage;
			try {
				
				mimeMessage = MailReader.getMimeMessage(service, user, fullM.getId());
				
				System.out.println("\n Message number " + i);
				System.out.println("From: " + mimeMessage.getHeader("From", null));
				System.out.println("Subject: " + mimeMessage.getSubject());
				System.out.println("Body: " + MailHelper.getText(mimeMessage));
				System.out.println("\n");
				
				mimeMessages.add(mimeMessage);
	        
			} catch (MessagingException e) {
				e.printStackTrace();
			}	
        }
        
        System.out.println("Select a message to decrypt:");
        BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
	        
	    String answerStr = reader.readLine();
	    Integer answer = Integer.parseInt(answerStr);
	    
		MimeMessage chosenMessage = mimeMessages.get(answer);
		
		// iz tela mejla izvlacimo deo sa enkriptovanom porukom
		String messageContent = chosenMessage.getContent().toString();
		String[] csv = messageContent.split("\\s\\s");
		System.out.println("csv: "+csv[1]);
		
		// iz tela mejla izvlacimo deo sa enkriptovanim (tajnim) session kljucem
		MailBody mailBody = new MailBody(csv[1]);
		byte[] cipherSecretKey = mailBody.getEncKeyBytes();
		System.out.println("cipherSecretKey: " + Base64.encodeToString(cipherSecretKey));
		
		// ucitavanje "userb.jks" keystore file-a
		KeyStore keyStore = keyStoreReader.readKeyStore(USERB_KS, USERB_KS_PASS.toCharArray());
		
		// preuzimanje privatnog kljuca usera b iz keystore file-a
		PrivateKey privateKey = keyStoreReader.getPrivateKeyFromKeyStore(keyStore, USERB_KS_ALIAS, USERB_KS_PASS_FOR_ALIAS.toCharArray());
		System.out.println("Privatni kljuc user b: " + privateKey);
		
		//dekriptovanje poruke privatnim kljucem
		Cipher rsaCipherDec = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		
		//inicijalizacija za dekriptovanje
		//dekriptovanje se vrsi privatnim kljucem usera b
		rsaCipherDec.init(Cipher.DECRYPT_MODE, privateKey);
		
		//dekriptovanje tajnog kljuca
		byte[] decryptedKey = rsaCipherDec.doFinal(cipherSecretKey);
		System.out.println("Dekriptovan kljuc: " + decryptedKey.toString());
		
	    
        //TODO: Decrypt a message and decompress it. The private key is stored in a file.
		Cipher aesCipherDec = Cipher.getInstance("AES/CBC/PKCS5Padding");
		SecretKey secretKey = new SecretKeySpec(decryptedKey, "AES");
		
		// getujemo IV1 bajtove iz tela poruke
		byte[] iv1 = mailBody.getIV1Bytes();
		IvParameterSpec ivParameterSpec1 = new IvParameterSpec(iv1);
		aesCipherDec.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec1);
		
		String string = csv[0];
		byte[] bodyEnc = Base64.decode(string);
		
		String receivedBodyTxt = new String(aesCipherDec.doFinal(bodyEnc));
		String decompressedBodyText = GzipUtil.decompress(Base64.decode(receivedBodyTxt));
		System.out.println("Body text: " + decompressedBodyText);
		
		// getujemo IV2 bajtove iz tela poruke
		byte[] iv2 = mailBody.getIV2Bytes();
		IvParameterSpec ivParameterSpec2 = new IvParameterSpec(iv2);
		
		//inicijalizacija za dekriptovanje
		aesCipherDec.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec2);
		
		//dekompresovanje i dekriptovanje subject-a
		String decryptedSubjectTxt = new String(aesCipherDec.doFinal(Base64.decode(chosenMessage.getSubject())));
		String decompressedSubjectTxt = GzipUtil.decompress(Base64.decode(decryptedSubjectTxt));
		System.out.println("Subject: " + new String(decompressedSubjectTxt));
		System.out.println("Body text: " + new String(decompressedBodyText));
	}
}
