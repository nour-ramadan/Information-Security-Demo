/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package ca;

import crypto.SSLCertificate;
import helper.Config;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.HashMap;

/**
 *
 * @author Nour Eddin
 */
public class CA {

    private static ServerSocket serverSocket;
    private static KeyPair keyPair;
    
    public static void init() throws Exception{
        
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        
        keyPair = keyGen.generateKeyPair();
    }
    
    public static KeyPair getKeyPair(){
        return keyPair;
    }
    
    public static void main(String[] args) throws Exception{
        
        init();
        System.out.println("CA server has successfully started.");
        
        serverSocket = new ServerSocket(Config.CA_PORT);
        
        while(true){
            
            Socket socket = serverSocket.accept();
            new CAThread(socket).start();
        }
    }
}
