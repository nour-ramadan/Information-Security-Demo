/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package helper;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.logging.Level;
import java.util.logging.Logger;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.nio.charset.Charset;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

/**
 *
 * @author Nour Eddin
 */
public class DB {
    
    public static void addUserToPool(String name, String encodedPublicKey) throws Exception{
        
        DateFormat dateFormat = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss");
        DocumentBuilderFactory documentBuildreFactory = DocumentBuilderFactory.newInstance();
        DocumentBuilder documentBuilder = documentBuildreFactory.newDocumentBuilder();
        Document document = documentBuilder.parse(new File(Config.PATH));
        
        Element root = document.getDocumentElement();
        Element user = document.createElement("user");
        Element username = document.createElement("username");
        Element key = document.createElement("publickey");
        Element date = document.createElement("date");
        
        username.appendChild(document.createTextNode(name));
        key.appendChild(document.createTextNode(encodedPublicKey));
        date.appendChild(document.createTextNode(dateFormat.format(new Date())));
        user.appendChild(username);
        user.appendChild(key);
        user.appendChild(date);
        root.appendChild(user);
        
        DOMSource source = new DOMSource(document);
        TransformerFactory transformerFactory = TransformerFactory.newInstance();
        Transformer transformer = transformerFactory.newTransformer();
        transformer.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "2");
        transformer.setOutputProperty(OutputKeys.INDENT, "yes");
        StreamResult result = new StreamResult(Config.PATH);
        transformer.transform(source, result);
    }
    
    public static boolean existsInUsersPool(String name) throws Exception{
        
        DocumentBuilderFactory documentBuildreFactory = DocumentBuilderFactory.newInstance();
        DocumentBuilder documentBuilder = documentBuildreFactory.newDocumentBuilder();
        Document document = documentBuilder.parse(new File(Config.PATH));
        
        Element root = document.getDocumentElement();
        
        NodeList users = root.getChildNodes();
        int count = users.getLength();
        
        for(int i = 0; i < count; i++){
            
            if (users.item(i).getNodeType() != Node.ELEMENT_NODE) continue;
            
            Element user = (Element)users.item(i);
            String username = user.getElementsByTagName("username").item(0).getTextContent();
            
            if(username.equals(name)) return true;
        }
        return false;
    }
    
    public static ArrayList<String> getAllUsers() throws Exception{
        
        ArrayList<String> result = new ArrayList<>();
        
        DocumentBuilderFactory documentBuildreFactory = DocumentBuilderFactory.newInstance();
        DocumentBuilder documentBuilder = documentBuildreFactory.newDocumentBuilder();
        Document document = documentBuilder.parse(new File(Config.PATH));
        
        Element root = document.getDocumentElement();
        
        NodeList users = root.getChildNodes();
        int count = users.getLength();
        
        for(int i = 0; i < count; i++){
            
            if (users.item(i).getNodeType() != Node.ELEMENT_NODE) continue;
            
            Element user = (Element)users.item(i);
            String username = user.getElementsByTagName("username").item(0).getTextContent();
            result.add(username);
        }
        
        return result;
    }
    
    public static String encodePublicKey(PublicKey publicKey) throws Exception{
        
        byte[] publicBytes = Base64.getEncoder().encode(publicKey.getEncoded());
        return new String(publicBytes);
    }
    
    public static PublicKey decodePublicKey(String publicKey) throws Exception{
        
        byte[] bytes = Base64.getDecoder().decode(publicKey.getBytes());
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(bytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(keySpec);
    }
    
    public static String getEncodedUserPublicKey(String name) throws Exception{
        
        DocumentBuilderFactory documentBuildreFactory = DocumentBuilderFactory.newInstance();
        DocumentBuilder documentBuilder = documentBuildreFactory.newDocumentBuilder();
        Document document = documentBuilder.parse(new File(Config.PATH));
        
        Element root = document.getDocumentElement();
        
        NodeList users = root.getChildNodes();
        int count = users.getLength();
        
        for(int i = 0; i < count; i++){
            
            if (users.item(i).getNodeType() != Node.ELEMENT_NODE) continue;
            
            Element user = (Element)users.item(i);
            String username = user.getElementsByTagName("username").item(0).getTextContent();
            
            if(username.equals(name)){
                
                String serializedKey = user.getElementsByTagName("publickey").item(0).getTextContent();
                return serializedKey;
            }
        }
        
        throw new Exception("User does not exist");
    }
    
    public static void signOut(String name) throws Exception{
        
        DocumentBuilderFactory documentBuildreFactory = DocumentBuilderFactory.newInstance();
        DocumentBuilder documentBuilder = documentBuildreFactory.newDocumentBuilder();
        Document document = documentBuilder.parse(Config.PATH);
        
        Element root = document.getDocumentElement();
        
        NodeList users = root.getChildNodes();
        int count = users.getLength();
        boolean ok = false;
        
        for(int i = 0; i < count; i++){
            
            if (users.item(i).getNodeType() != Node.ELEMENT_NODE) continue;
            
            Element user = (Element)users.item(i);
            String username = user.getElementsByTagName("username").item(0).getTextContent();
            
            if(username.equals(name)){
                root.removeChild(users.item(i));
                System.out.println("User " + username + " has signed out");
                ok = true;
                break;
            }
        }
        
        DOMSource source = new DOMSource(document);
        TransformerFactory transformerFactory = TransformerFactory.newInstance();
        Transformer transformer = transformerFactory.newTransformer();
        transformer.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "2");
        transformer.setOutputProperty(OutputKeys.INDENT, "yes");
        StreamResult result = new StreamResult(Config.PATH);
        transformer.transform(source, result);
    }
    
}
