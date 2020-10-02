package xml.crypto;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.cert.Certificate;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.xml.security.encryption.EncryptedData;
import org.apache.xml.security.encryption.EncryptedKey;
import org.apache.xml.security.encryption.XMLCipher;
import org.apache.xml.security.keys.KeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import keystore.KeyStoreReader;

//Generise tajni kljuc
//Kriptije sadrzaj elementa email tajnim kljucem
//Kriptuje tajni kljuc javnim kljucem
//Kriptovani tajni kljuc se stavlja kao KeyInfo kriptovanog elementa

public class AsymmetricKeyEncryption {
	
	private static final String IN_FILE = "./data/mailsent_signed.xml";
	private static final String OUT_FILE = "./data/mailsent_signed_encrypted.xml";
	private static final String KEY_STORE_FILE = "./data/usera.jks";
	private static final String KEY_STORE_PASSWORD = "1234";
	
	// Treba nam javni kljuc usera b iz njegovog sertifikata koji se nalazi u keystore fajlu usera a
	private static final String KEY_STORE_ALIAS_USERB = "userb";
	
	private static KeyStoreReader keyStoreReader = new KeyStoreReader();

	static {
		// staticka inicijalizacija
		Security.addProvider(new BouncyCastleProvider());
		org.apache.xml.security.Init.init();
	}

	public static void testIt() {
		// ucitava se dokument
		Document doc = loadDocument(IN_FILE);
		
		// generise tajni session kljuc
		System.out.println("Generating secret key ....");
		SecretKey secretKey = generateDataEncryptionKey();
		
		// ucitava sertifikat za kriptovanje tajnog kljuca javnim kljucem primaoca poruke
		//Certificate cert = readCertificate();
		
		// ucitavanje "usera.jks" keystore file-a (za potrebe dobavljanja javnog kljuca iz sertifikata usera b)
		KeyStore keyStore = keyStoreReader.readKeyStore(KEY_STORE_FILE, KEY_STORE_PASSWORD.toCharArray());
		
		// ucitava sertifikat za kriptovanje tajnog kljuca javnim kljucem primaoca poruke
		// preuzimanje sertifikata userb iz keystore file-a "usera.jks"
		Certificate cert = keyStoreReader.getCertificateFromKeyStore(keyStore, KEY_STORE_ALIAS_USERB);
		
		// kriptuje se dokument
		System.out.println("Encrypting....");
		doc = encrypt(doc, secretKey, cert);
		
		// snima se tajni kljuc
		// snima se dokument
		saveDocument(doc, OUT_FILE);
		
		System.out.println("Encryption done");
	}

	/**
	 * Kreira DOM od XML dokumenta
	 */
	private static Document loadDocument(String file) {
		try {
			DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
			dbf.setNamespaceAware(true);
			DocumentBuilder db = dbf.newDocumentBuilder();
			Document document = db.parse(new File(file));

			return document;
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		} 
	}

	/**
	 * Ucitava sertifikat is KS fajla usera.jks (alias "usera")
	 */
	private static Certificate readCertificate() {
		try {
			// kreiramo instancu KeyStore
			KeyStore ks = KeyStore.getInstance("JKS", "SUN");
			// ucitavamo podatke
			BufferedInputStream in = new BufferedInputStream(new FileInputStream(KEY_STORE_FILE));
			ks.load(in, KEY_STORE_PASSWORD.toCharArray());

			if (ks.isKeyEntry(KEY_STORE_ALIAS_USERB)) {
				Certificate cert = ks.getCertificate(KEY_STORE_ALIAS_USERB);
				return cert;
			} else
				return null;

		} catch (Exception e) {
			e.printStackTrace();
			return null;
		} 
	}
	

	/**
	 * Snima DOM u XML fajl
	 */
	private static void saveDocument(Document doc, String fileName) {
		try {
			File outFile = new File(fileName);
			FileOutputStream f = new FileOutputStream(outFile);

			TransformerFactory factory = TransformerFactory.newInstance();
			Transformer transformer = factory.newTransformer();

			DOMSource source = new DOMSource(doc);
			StreamResult result = new StreamResult(f);

			transformer.transform(source, result);

			f.close();

		} catch (Exception e) {
			e.printStackTrace();
		} 
	}

	/**
	 * Generise tajni kljuc
	 */
	private static SecretKey generateDataEncryptionKey() {

		try {
			KeyGenerator keyGenerator = KeyGenerator.getInstance("DESede"); // Triple
																			// DES
			return keyGenerator.generateKey();

		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			return null;
		}
	}

	/**
	 * Kriptovanje poruke
	 */
	private static Document encrypt(Document doc, SecretKey key, Certificate certificate) {

		try {

			// cipher za kriptovanje XML-a
			XMLCipher xmlCipher = XMLCipher.getInstance(XMLCipher.TRIPLEDES);
			
			// inicijalizacija za kriptovanje
			xmlCipher.init(XMLCipher.ENCRYPT_MODE, key);

			// cipher za kriptovanje tajnog kljuca,
			// Koristi se Javni RSA kljuc za kriptovanje
			XMLCipher keyCipher = XMLCipher.getInstance(XMLCipher.RSA_v1dot5);
			
			// inicijalizacija za kriptovanje tajnog kljuca javnim RSA kljucem
			keyCipher.init(XMLCipher.WRAP_MODE, certificate.getPublicKey());
			System.out.println("Public key B: " + certificate.getPublicKey());
			
			// kreiranje EncryptedKey objekta koji sadrzi  enkriptovan tajni (session) kljuc
			EncryptedKey encryptedKey = keyCipher.encryptKey(doc, key);
			
			// u EncryptedData element koji se kriptuje kao KeyInfo stavljamo
			// kriptovan tajni kljuc
			// ovaj element je koreni element XML enkripcije
			EncryptedData encryptedData = xmlCipher.getEncryptedData();
			
			// kreira se KeyInfo element
			KeyInfo keyInfo = new KeyInfo(doc);
			
			// postavljamo naziv 
			keyInfo.addKeyName("Kriptovani tajni kljuc");
			
			// postavljamo kriptovani kljuc
			keyInfo.add(encryptedKey);
			
			// postavljamo KeyInfo za element koji se kriptuje
			encryptedData.setKeyInfo(keyInfo);

			// trazi se element ciji sadrzaj se kriptuje
			// emails = lista cvoreva - svi elementi koji imaju tag "email"
			NodeList emails = doc.getElementsByTagName("email");
			// prvi email element iz liste svih email elemenata
			Element email = (Element) emails.item(0);			
			
			xmlCipher.doFinal(doc, doc.getDocumentElement(), true); // kriptuje se sadrzaj
			System.out.println("Encryption done");

			return doc;

		} catch (Exception e) {
			e.printStackTrace();
			return null;
		} 
	}

	/*public static void main(String[] args) {
		AsymmetricKeyEncryption encrypt = new AsymmetricKeyEncryption();
		encrypt.testIt();
	}*/
}
