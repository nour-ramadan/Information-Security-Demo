/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package server;

import crypto.SSLCertificate;
import helper.DB;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.util.ArrayList;


/**
 *
 * @author Nour Eddin
 */
public class ServerThread extends Thread{
    
    private final Socket socket;
    private final DataInputStream in;
    private final DataOutputStream out;
    
    public ServerThread(Socket socket) throws Exception{
        
        this.socket = socket;
        this.in = new DataInputStream(socket.getInputStream());
        this.out = new DataOutputStream(socket.getOutputStream());
    }
    
    private void signIn() throws Exception{
        
        String name = in.readUTF();
        String encodedPublicKey = in.readUTF();
        Server.setClientSocket(name, socket);
        DB.addUserToPool(name, encodedPublicKey);
        out.writeInt(200);
    }
    
    private void getAvailableUsers() throws Exception{
        
        out.writeInt(2);
        
        ArrayList<String> users = DB.getAllUsers();
        out.writeInt(users.size());
        for (String user : users) {
            out.writeUTF(user);
        }
    }
    
    private void sendMessage() throws Exception{
        
        String senderName = in.readUTF();
        String receiverName = in.readUTF();
        String msg = in.readUTF();
        
        Socket cSocket = Server.getClientSocket(receiverName);
        DataOutputStream cOut = new DataOutputStream(cSocket.getOutputStream());
        
        cOut.writeInt(3);
        cOut.writeUTF(senderName);
        cOut.writeUTF(msg);
    }
    
    private void sendMessageEncryptedWithAES() throws Exception{
        
        String senderName = in.readUTF();
        String recvName = in.readUTF();
        String salt = in.readUTF();
        int msgLen = in.readInt();
        byte[] encryptedMessage = new byte[msgLen];
        in.read(encryptedMessage);
        
        Socket cSocket = Server.getClientSocket(recvName);
        DataOutputStream cOut = new DataOutputStream(cSocket.getOutputStream());
        
        cOut.writeInt(4);
        cOut.writeUTF(senderName);
        cOut.writeUTF(salt);
        cOut.writeInt(msgLen);
        cOut.write(encryptedMessage);
    }
    
    private void sendMessageEncryptedWithRSA() throws Exception{
        
        String senderName = in.readUTF();
        String recvName = in.readUTF();
        int msgLen = in.readInt();
        byte[] encryptedMessage = new byte[msgLen];
        in.read(encryptedMessage);
        
        Socket cSocket = Server.getClientSocket(recvName);
        DataOutputStream cOut = new DataOutputStream(cSocket.getOutputStream());
        
        cOut.writeInt(1000);
        cOut.writeUTF(senderName);
        cOut.writeInt(encryptedMessage.length);
        cOut.write(encryptedMessage);
    }
    
    private void sendMessageEncryptedWithPGBandSignture() throws Exception{
        
        String senderName = in.readUTF();
        String recvName = in.readUTF();
        int encryptedMsgLen = in.readInt();
        int encryptedSecretKeyLen = in.readInt();
        int signedHashLen = in.readInt();
        byte[] msg = new byte[encryptedMsgLen + encryptedSecretKeyLen + signedHashLen];
        in.read(msg);
        
        Socket cSocket = Server.getClientSocket(recvName);
        DataOutputStream cOut = new DataOutputStream(cSocket.getOutputStream());
        
        cOut.writeInt(2000);
        cOut.writeUTF(senderName);
        cOut.writeInt(encryptedMsgLen);
        cOut.writeInt(encryptedSecretKeyLen);
        cOut.writeInt(signedHashLen);
        cOut.write(msg);
    }
    
    private void getClientCertificate() throws Exception{
        
        String senderName = in.readUTF();
        String recvName = in.readUTF();
        
        Socket cSocket = Server.getClientSocket(recvName);
        DataOutputStream cOut = new DataOutputStream(cSocket.getOutputStream());
        
        cOut.writeInt(3000);
        cOut.writeUTF(senderName);
    }
    
    private void getClientCertificate_2() throws Exception{
        
        String recvName = in.readUTF();
        
        ObjectInputStream objectIn = new ObjectInputStream(this.socket.getInputStream());
        
        SSLCertificate SSLCert = (SSLCertificate)objectIn.readObject();
        
        Socket cSocket = Server.getClientSocket(recvName);
        
        DataOutputStream cOut = new DataOutputStream(cSocket.getOutputStream());
        
        cOut.writeInt(3010);
        cOut.writeInt(-1);
        
        ObjectOutputStream objectOut = new ObjectOutputStream(cSocket.getOutputStream());
        objectOut.writeObject(SSLCert);
    }
            
    @Override
    public void run(){
        
        while (true) {
            try{
                
                int type = in.readInt();
                
                if(type == 1){ // sign in
                    
                    signIn();
                }
                else if(type == 2){ // get all online users
                    
                    getAvailableUsers();
                }
                else if(type == 3){ // send message
                    
                    sendMessage();
                }
                else if(type == 4){ // send message encrypted with AES
                    
                    sendMessageEncryptedWithAES();
                }
                else if(type == 1000){ // send message ecrypted with RSA
                    
                    sendMessageEncryptedWithRSA();
                }
                else if(type == 2000){ // send message encrypted with PGB
                    
                    sendMessageEncryptedWithPGBandSignture();
                }
                else if(type == 3000){ // get a client certificate
                    
                    getClientCertificate();
                }
                else if(type == 3010){ // get a client certificate back to the asker
                    
                    getClientCertificate_2();
                }

            }catch(Exception ex){System.out.println(ex.getMessage());}
        }
    }
}
