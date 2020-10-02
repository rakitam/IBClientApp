package app;


import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.io.StringWriter;
import java.security.KeyStore;
import java.security.PublicKey;

import javax.activation.DataHandler;
import javax.activation.DataSource;
import javax.activation.FileDataSource;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.mail.BodyPart;
import javax.mail.Message;
import javax.mail.MessagingException;
import javax.mail.Multipart;
import javax.mail.Session;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.MimeMultipart;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import java.security.cert.Certificate;
import java.util.Properties;
import java.util.Base64.Encoder;

import org.apache.xml.security.utils.JavaUtils;

import com.google.api.services.gmail.Gmail;

import keystore.KeyStoreReader;
import model.mailclient.MailBody;
import util.Base64;
import util.GzipUtil;
import util.IVHelper;
import xml.crypto.AsymmetricKeyEncryption;
import xml.signature.SignEnveloped;
import support.MailHelper;
import support.MailWritter;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

public class WriteMailClient extends MailClient {

	private static final String KEY_FILE = "./data/session.key";
	private static final String IV1_FILE = "./data/iv1.bin";
	private static final String IV2_FILE = "./data/iv2.bin";
	
	private static final String USERA_KS = "./data/usera.jks";
	private static final String USERA_KS_PASS = "1234";
	private static final String USERB_KS_ALIAS = "userb";
	
	public static final String XML_FILE_PATH = "./data/mailsent.xml";	
	private static final String XML_ENC_MESSAGE_PATH = "./data/mailsent_signed_encrypted.xml";
	
	private static KeyStoreReader keyStoreReader = new KeyStoreReader();
	
	public static void main(String[] args) {
		
        try {
        	Gmail service = getGmailService();
            
        	System.out.println("Insert a reciever:");
            BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
            String reciever = reader.readLine();
        	
            System.out.println("Insert a subject:");
            String subject = reader.readLine();            
            
            System.out.println("Insert body:");
            String body = reader.readLine(); 
            
            // Kreiramo XML file i kreiramo textNodes sa unetim vrednostima subject i body
            createXML(subject, body);
            System.out.println("Kreiran XML fajl");
            
            // Potpisujemo XML file (prolazi kroz transformaciju, dodaje se signature node, snima se potpisan dokument)
            SignEnveloped.testIt();
            System.out.println("XML fajl potpisan");
            
	        // Enkriptovanje
	        AsymmetricKeyEncryption.testIt();
	        System.out.println("XML fajl enkriptovan");
	        
	        // Konvertovanje enkriptovanog XML dokumenta u DOM
	        Document encrDoc = convertXMLFileToXMLDocument(XML_ENC_MESSAGE_PATH);
	        
	        // Pretvaranje XML-a u String
	        String xmlString = XmlDocumentToString(encrDoc);
	        System.out.println(xmlString);
	        
	        // Slanje enkriptovanog XML-a u body-ju poruke	        
	        MimeMessage mimeMessage = MailHelper.createMimeMessage(reciever, "Encrypted message", xmlString);
        	MailWritter.sendMessage(service, "me", mimeMessage);  	          
	                    
                                  
            /* 
             * Bez potpisa, CSV format poruka koje se razmenjuju - KONTROLNA TACKA
             * 
             * //Compression
            String compressedSubject = Base64.encodeToString(GzipUtil.compress(subject));
            String compressedBody = Base64.encodeToString(GzipUtil.compress(body));
            
            //Key generation
            KeyGenerator keyGen = KeyGenerator.getInstance("AES"); 
			SecretKey secretKey = keyGen.generateKey();
			Cipher aesCipherEnc = Cipher.getInstance("AES/CBC/PKCS5Padding");
			
			//inicijalizacija za sifrovanje 
			IvParameterSpec ivParameterSpec1 = IVHelper.createIV();
			aesCipherEnc.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec1);
			
			
			//sifrovanje
			byte[] ciphertext = aesCipherEnc.doFinal(compressedBody.getBytes());
			String ciphertextStr = Base64.encodeToString(ciphertext);
			System.out.println("Kriptovan tekst: " + ciphertextStr);
			
			
			//inicijalizacija za sifrovanje 
			IvParameterSpec ivParameterSpec2 = IVHelper.createIV();
			aesCipherEnc.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec2);
			
			byte[] ciphersubject = aesCipherEnc.doFinal(compressedSubject.getBytes());
			String ciphersubjectStr = Base64.encodeToString(ciphersubject);
			System.out.println("Kriptovan subject: " + ciphersubjectStr);
			
			// ucitavanje "usera.jks" keystore file-a
			KeyStore keyStore = keyStoreReader.readKeyStore(USERA_KS, USERA_KS_PASS.toCharArray());
			
			// preuzimanje sertifikata userb iz keystore file-a "usera.jks"
			Certificate certificate = keyStoreReader.getCertificateFromKeyStore(keyStore, USERB_KS_ALIAS);
			
			// preuzimanje javnog kljuca usera b iz ucitanog sertifikata
			PublicKey publicKey = keyStoreReader.getPublicKeyFromCertificate(certificate);
			System.out.println("\nProcitan javni kljuc iz sertifikata: " + publicKey);
			
			//kriptovanje tajnog session kljuca javnim kljucem usera b
			Cipher rsaCipherEnc = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			
			//inicijalizacija za kriptovanje, 
			//kod asimetricnog algoritma kriptuje se javnim kljucem, a dekriptuje privatnim
			rsaCipherEnc.init(Cipher.ENCRYPT_MODE, publicKey);
			
			//kriptovanje
			byte[] cipherSecretKey = rsaCipherEnc.doFinal(secretKey.getEncoded());
			System.out.println("cipherSecretKey sifrovao sam: " + Base64.encodeToString(cipherSecretKey));			
			
			//snimaju se bajtovi kljuca i IV.
			JavaUtils.writeBytesToFilename(KEY_FILE, secretKey.getEncoded());
			JavaUtils.writeBytesToFilename(IV1_FILE, ivParameterSpec1.getIV());
			JavaUtils.writeBytesToFilename(IV2_FILE, ivParameterSpec2.getIV());			
			
			// enkriptovani javni kljuc prenosimo u okviru tela mejla
			MailBody mailBody = new MailBody(ciphertext, ivParameterSpec1.getIV(), ivParameterSpec2.getIV(), cipherSecretKey);
			String csv = mailBody.toCSV();
			
        	MimeMessage mimeMessage = MailHelper.createMimeMessage(reciever, ciphersubjectStr, ciphertextStr + " " + csv);
        	MailWritter.sendMessage(service, "me", mimeMessage); */
        	
        }catch (Exception e) {
        	e.printStackTrace();
		}
	}
	
	// Kreiranje XML dokumenta
	public static void createXML(String subject, String body) {
		
		DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
	    DocumentBuilder documentBuilder;
	    
	    try {
	    	documentBuilder = dbFactory.newDocumentBuilder();
	    	Document doc = documentBuilder.newDocument();
	    	Element rootElement = doc.createElement("email");
	    	doc.appendChild(rootElement);
	    	
	    	Element subjectEl = doc.createElement("subject");
	    	subjectEl.appendChild(doc.createTextNode(subject));
	    	
	    	Element bodyEl = doc.createElement("body");
	    	bodyEl.appendChild(doc.createTextNode(body));
	    	
	    	rootElement.appendChild(subjectEl);
	    	rootElement.appendChild(bodyEl);
	    	
	    	//Transformisemo XML u DOM
	    	Transformer transformer = TransformerFactory.newInstance().newTransformer();
    		transformer.setOutputProperty(OutputKeys.INDENT, "yes"); 
	        DOMSource source = new DOMSource(doc);
	         
	        StreamResult streamResult = new StreamResult(new File(XML_FILE_PATH));
	        transformer.transform(source, streamResult);

	 		System.out.println("Sacuvan fajl!");
	 		
	    } catch (Exception e) {
	         e.printStackTrace();
	    } 
	}	
	
	// Kreiranje poruke
    public static MimeMessage createMessageWithAttachment(String reciever, String filename) throws MessagingException {
    	
    	Properties props = new Properties();
	    Session session = Session.getDefaultInstance(props, null);
    	MimeMessage message = new MimeMessage(session);

    	BodyPart messageBodyPart1 = new MimeBodyPart();  
        messageBodyPart1.setText("This message is encrypted");
    	
    	BodyPart messageBodyPart = new MimeBodyPart();
    	DataSource source = new FileDataSource(filename);
    	messageBodyPart.setDataHandler(new DataHandler(source));
    	messageBodyPart.setFileName(filename);
    	
    	Multipart multipart = new MimeMultipart();
    	multipart.addBodyPart(messageBodyPart1);
    	multipart.addBodyPart(messageBodyPart);
    	
    	message.setSubject("Encrypted XML message");
    	message.setRecipient(Message.RecipientType.TO, new InternetAddress(reciever));
    	message.setContent(multipart);
    	
    	return message;
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
            //transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
             
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
}
