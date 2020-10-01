package app;


import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.security.KeyStore;
import java.security.PublicKey;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.mail.internet.MimeMessage;

import java.security.cert.Certificate;

import org.apache.xml.security.utils.JavaUtils;

import com.google.api.services.gmail.Gmail;

import keystore.KeyStoreReader;
import model.mailclient.MailBody;
import util.Base64;
import util.GzipUtil;
import util.IVHelper;
import xml.signature.SignEnveloped;
import support.CreateXMLFile;
import support.MailHelper;
import support.MailWritter;

public class WriteMailClient extends MailClient {

	private static final String KEY_FILE = "./data/session.key";
	private static final String IV1_FILE = "./data/iv1.bin";
	private static final String IV2_FILE = "./data/iv2.bin";
	
	private static final String USERA_KS = "./data/usera.jks";
	private static final String USERA_KS_PASS = "1234";
	private static final String USERB_KS_ALIAS = "userb";
	
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
            CreateXMLFile.createXML(subject, body);
            System.out.println("Kreiran XML fajl");
            
            // Potpisujemo XML file (prolazi kroz transformaciju, dodaje se signature node, snima se potpisan dokument)
            SignEnveloped.testIt();
            System.out.println("XML fajl potpisan");
            
            
            
                      
            /* 
             * Bez potpisa, CSV format poruka koje se razmenjuju
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
}
