package app;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.StringReader;
import java.io.StringWriter;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Security;
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
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

//import org.apache.xml.security.utils.JavaUtils;

import com.google.api.services.gmail.Gmail;
import com.google.api.services.gmail.model.Message;

import keystore.KeyStoreReader;
import model.mailclient.MailBody;
import support.MailHelper;
import support.MailReader;
import util.Base64;
import util.GzipUtil;
import xml.crypto.AsymmetricKeyDecryption;
import xml.signature.VerifySignatureEnveloped;

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
	
	private static final String RECIEVED_ENC_EMAIL = "./data/mail_recieved_encrypted.xml";
	private static final String RECIEVED_DEC_EMAIL = "./data/mail_recieved_decrypted.xml";
	
	private static KeyStoreReader keyStoreReader = new KeyStoreReader();
	
	static {
		// staticka inicijalizacija
		// postavljamo provider-a; potrebno za RSA dekripciju
		Security.addProvider(new BouncyCastleProvider());
		org.apache.xml.security.Init.init();
	}
	
	
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
		

		/*
		 * 1. Dekripcija i verifikacija enkriptovane i potpisane XML poruke
		 */
		// Preuzimamo enkriptovanu XML poruku u String formatu
		String xmlString = MailHelper.getText(chosenMessage);
		System.out.println("Stampam getText: " + xmlString);
		
		// Od preuzete poruke kreiramo XML dokument
		Document doc = convertStringToXMLDocument(xmlString);
		System.out.println("XML kreiran");
		
		//Cuvamo dokument u fajl sistemu (zbog provere)
		AsymmetricKeyDecryption.saveDocument(doc, RECIEVED_ENC_EMAIL);
		System.out.println("Fajl sacuvan");
		
		// Dekriptujemo fajl
		AsymmetricKeyDecryption.testIt();
		System.out.println("Fajl dekriptovan");
		
		Document decrDoc = convertXMLFileToXMLDocument(RECIEVED_DEC_EMAIL);
		
		// Verifikujemo potpis - ukoliko integritet i neporecivost poruke nisu naruseni, 
		//prikazujemo dekriptovan sadrzaj
		if (VerifySignatureEnveloped.testIt()) {
			System.out.println("Potpis verifikovan.");
			printContent(decrDoc);			
		} 
		
		else {
			System.out.println("Potpis nije validan.");			
		}
		
		// Prikaz slucaja kada se menja sadrzaj poruke - narusen integritet
		VerifySignatureEnveloped.testItFaulty();
		System.out.println("Narusen integritet poruke - sadrzaj je izmenjen.");		
		
		
		
		/* 
		 * 2. Dekripcija poruke; bez potpisa - KONTROLNA TACKA
		 *
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
	    
        //Decrypt a message and decompress it. The private key is stored in a file.
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
		System.out.println("Body text: " + new String(decompressedBodyText)); */
	}
	
	// Konvertujemo enkriptovani String u XMLDocument
	private static Document convertStringToXMLDocument(String xmlString) 
    {
		Document doc = null;
        //Parser that produces DOM object trees from XML content
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
         
        //API to obtain DOM Document instance
        DocumentBuilder builder = null;
        try
        {
            //Create DocumentBuilder with default configuration
            builder = factory.newDocumentBuilder();
             
            //Parse the content to Document object
            doc = builder.parse(new InputSource(new StringReader(xmlString)));
            return doc;
        } 
        catch (Exception e) 
        {
            e.printStackTrace();
        }
        return doc;
    }
	
	// Konvertovanje XML-a u DOM
    private static Document convertXMLFileToXMLDocument(String filePath) 
    {
        //Parser that produces DOM object trees from XML content
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
         
        //API to obtain DOM Document instance
        DocumentBuilder builder = null;
        try
        {
            //Create DocumentBuilder with default configuration
            builder = factory.newDocumentBuilder();
             
            //Parse the content to Document object
            Document xmlDocument = builder.parse(new File(filePath));
             
            return xmlDocument;
        } 
        catch (Exception e) 
        {
            e.printStackTrace();
        }
        return null;
    }
	
	// Konvertovanje XML dokumenta u String
    private static String XmlDocumentToString(Document xmlDocument) {
    	
        TransformerFactory tf = TransformerFactory.newInstance();
        Transformer transformer;
        String xmlString = null;
        
        try {
            transformer = tf.newTransformer();
             
            // Uncomment if you do not require XML declaration
            transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
             
            //A character stream that collects its output in a string buffer, 
            //which can then be used to construct a string.
            StringWriter writer = new StringWriter();
     
            //transform document to string 
            transformer.transform(new DOMSource(xmlDocument), new StreamResult(writer));
     
            xmlString = writer.getBuffer().toString();   
            System.out.println(xmlString);                      //Print to console or logs
        } 
        catch (TransformerException e) 
        {
            e.printStackTrace();
        }
        catch (Exception e) 
        {
            e.printStackTrace();
        }
		return xmlString;
    }
    
    // Print sadrzaj mejla
 	public static void printContent(Document doc) {
 		Node fc = doc.getFirstChild();
 		NodeList list = fc.getChildNodes();
 		for (int i = 0; i <list.getLength(); i++) {
 			Node node = list.item(i);
 			if("subject".equals(node.getNodeName())) {
 				System.out.println("Subject: " + node.getTextContent());
 			}
 			if("body".equals(node.getNodeName())) {
 				System.out.println("Body: " + node.getTextContent());
 			}
 		}
 	}
}
