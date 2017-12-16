/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package client;

import crypto.AES;
import crypto.RSA;
import crypto.SSLCertificate;
import crypto.Signature;
import helper.Config;
import helper.DB;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.ObjectInputStream;
import java.net.Socket;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

/**
 *
 * @author Nour Eddin
 */
public class Client {

    private String name;
    private Socket socket;
    private Socket caSocket;
    private KeyPair keyPair;
    private SSLCertificate SSLCert;
    ObjectInputStream in;
    
    // Setters and getters.
    public String getName(){
        return this.name;
    }
    
    public void setName(String name){
        this.name = name;
    }
    
    public Socket getSocket(){
        return this.socket;
    }
    
    public void setSocket(Socket socket){
        this.socket = socket;
    }
    
    public Socket getCaSocket(){
        return this.caSocket;
    }
    
    public void setcASocket(Socket socket){
        this.caSocket = socket;
    }
    
    public KeyPair getKeyPair(){
        return this.keyPair;
    }
    
    public void setKeyPair(KeyPair keyPair){
        this.keyPair = keyPair;
    }
    
    public SSLCertificate getSSLCert(){
        return SSLCert;
    }
    
    public void setSSLCert(SSLCertificate SSLCert){
        this.SSLCert = SSLCert;
    }
    
    public Client(String name) throws Exception{
        
        this.name = name;
        this.socket = new Socket(Config.HOST, Config.PORT);
        this.caSocket = new Socket(Config.HOST, Config.CA_PORT);
        this.SSLCert = new SSLCertificate();
        
        this.in = new ObjectInputStream(caSocket.getInputStream());
        
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(1024);
        
        this.keyPair = keyGen.generateKeyPair();
        
        if(signIn()){
            System.out.println("Client " + name + " has signed in successfully");
        }
        else{
            System.out.println("There was a problem in signing in client: " + name);
        }
    }
    
    private boolean signIn() throws Exception{
        
        DataInputStream in = new DataInputStream(socket.getInputStream());
        DataOutputStream out = new DataOutputStream(socket.getOutputStream());
        
        out.writeInt(1);
        out.writeUTF(name);
        out.writeUTF(DB.encodePublicKey(keyPair.getPublic()));
        
        int signal = in.readInt();
        return signal == 200; // success.
    }
    
    
    public void generateNewPair() throws Exception{
        
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(1024);
        
        this.keyPair = keyGen.generateKeyPair();
        
        DB.signOut(name);
        DB.addUserToPool(name, DB.encodePublicKey(keyPair.getPublic()));
    }
    
    public void getAllUsers() throws Exception{
        
        DataOutputStream out = new DataOutputStream(socket.getOutputStream());
        out.writeInt(2);
    }
    
    public void sendMessage(String msg, String recvName) throws Exception{
       
        DataOutputStream out = new DataOutputStream(socket.getOutputStream());
        
        out.writeInt(3);
        out.writeUTF(name);
        out.writeUTF(recvName);
        out.writeUTF(msg);
    }
    
    public void sendMessageEncryptedWithAES(String msg, String recvName) throws Exception{
        
        DataOutputStream out = new DataOutputStream(socket.getOutputStream());
        
        String salt = "spicy";
        String secretKey = AES.generateKey(1, 0, salt);
        byte[] encryptedMessage = AES.encrypt(msg.getBytes(), AES.stringToSecretKey(secretKey));
        
        out.writeInt(4);
        out.writeUTF(name);
        out.writeUTF(recvName);
        out.writeUTF(salt);
        out.writeInt(encryptedMessage.length);
        out.write(encryptedMessage);
    }
    
    public void sendMessageEncryptedWithRSA(String msg, String recvName) throws Exception{
        
        DataOutputStream out = new DataOutputStream(socket.getOutputStream());
        
        byte[] encryptedMessage = RSA.encrypt(msg.getBytes(), DB.decodePublicKey(DB.getEncodedUserPublicKey(recvName)));
        out.writeInt(1000);
        out.writeUTF(name);
        out.writeUTF(recvName);
        out.writeInt(encryptedMessage.length);
        out.write(encryptedMessage);
    }
    
    public void sendMessageEncryptedWithPGBandSignture(String msg, String recvName) throws Exception{
        
        DataOutputStream out = new DataOutputStream(socket.getOutputStream());
        
        String salt = "spicy";
        String secretKey = AES.generateKey(1, 0, salt);
        
        byte[] encryptedMessage = AES.encrypt(msg.getBytes(), AES.stringToSecretKey(secretKey));
        byte[] encryptedSecretKey = RSA.encrypt(secretKey.getBytes(), DB.decodePublicKey(DB.getEncodedUserPublicKey(recvName)));
        byte[] signedHash = Signature.sign(Signature.getHash(msg.getBytes()), this.keyPair.getPrivate());
        
        int encryptedMsgLen = encryptedMessage.length;
        int encryptedSecretKeyLen = encryptedSecretKey.length;
        int signedHashLen = signedHash.length;
        
        byte[] dataToBeSent = new byte[encryptedMsgLen + encryptedSecretKeyLen + signedHashLen];
        
        System.arraycopy(encryptedMessage, 0, dataToBeSent, 0, encryptedMsgLen);
        System.arraycopy(encryptedSecretKey, 0, dataToBeSent, encryptedMsgLen, encryptedSecretKeyLen);
        System.arraycopy(signedHash, 0, dataToBeSent, encryptedMsgLen + encryptedSecretKeyLen, signedHashLen);
        
        out.writeInt(2000);
        out.writeUTF(name);
        out.writeUTF(recvName);
        out.writeInt(encryptedMsgLen);
        out.writeInt(encryptedSecretKeyLen);
        out.writeInt(signedHashLen);
        out.write(dataToBeSent);
    }
    
    public SSLCertificate getSSLCertificate() throws Exception{
        
        DataOutputStream out = new DataOutputStream(caSocket.getOutputStream());
//        ObjectInputStream in = new ObjectInputStream(caSocket.getInputStream());
        
        out.writeInt(1);
        out.writeUTF(name);
        out.writeUTF(DB.encodePublicKey(keyPair.getPublic()));
        
        return (SSLCertificate)in.readObject();
    }
    
    public boolean validateSSLCertificate(SSLCertificate cert) throws Exception{
        
        DataOutputStream out = new DataOutputStream(caSocket.getOutputStream());
//        ObjectInputStream in = new ObjectInputStream(caSocket.getInputStream());
        
        out.writeInt(2);
        
        String pk = (String)in.readObject();
        
        return RSA.SSL_unsign(cert.getCertificate(), DB.decodePublicKey(pk)).equals(DB.encodePublicKey(cert.getPublicKey()));
    }
    
    public void getClientSSLCertificate(String clientName) throws Exception{
        
        DataOutputStream out = new DataOutputStream(socket.getOutputStream());
        
        out.writeInt(3000);
        out.writeUTF(name);
        out.writeUTF(clientName);
    }
}