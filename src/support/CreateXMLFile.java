package support;

import java.io.File;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

public class CreateXMLFile {
	
	public static final String xmlFilePath = "./data/mailsent.xml";
	 
	public static void createXML(String subject, String body) {
		
		DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
	    DocumentBuilder documentBuilder;
	    
	    try {
	    	documentBuilder = dbFactory.newDocumentBuilder();
	    	Document doc = documentBuilder.newDocument();
	    	Element mainRootElement = doc.createElement("email");
	    	doc.appendChild(mainRootElement);
	    	
	    	// Kreiramo cvorove sa vrednostima iz inputa i appendujemo ih na root cvor
	    	mainRootElement.appendChild(getEmailNodeElements(doc, "subject", subject));
	    	mainRootElement.appendChild(getEmailNodeElements(doc, "body", body));
	    	
	    	Transformer transformer = TransformerFactory.newInstance().newTransformer();
    		transformer.setOutputProperty(OutputKeys.INDENT, "yes"); 
	        DOMSource source = new DOMSource(doc);
	         
	        StreamResult streamResult = new StreamResult(new File(xmlFilePath));
	        transformer.transform(source, streamResult);

	 		System.out.println("Sacuvan fajl!");
	    } catch (Exception e) {
	         e.printStackTrace();
	    }
	}
	
	// Kreiramo cvor pod odredjenim imenom i dodeljujemo mu tekstualnu vrednost iz inputa
	private static Node getEmailNodeElements(Document doc, String name, String value) {
	     Element node = doc.createElement(name);
	     node.appendChild(doc.createTextNode(value));
	     return node;
	}

}
