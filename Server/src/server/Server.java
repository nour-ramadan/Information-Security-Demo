/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package server;

import java.net.ServerSocket;
import java.net.Socket;
import java.util.HashMap;
import helper.Config;

/**
 *
 * @author Nour Eddin
 */
public class Server {
    
    private static ServerSocket serverSocket;
    private static final HashMap<String,Socket> clients = new HashMap<>();
    
    public static Socket getClientSocket(String client){
        
        return clients.get(client);
    }
    
    public static void setClientSocket(String client, Socket socket){
        
        clients.put(client, socket);
    }
    
    public static void main(String[] args) throws Exception{
        
        System.out.println("Server has successfully started.");
        
        serverSocket = new ServerSocket(Config.PORT);
        
        while(true){
            
            Socket socket = serverSocket.accept();
            new ServerThread(socket).start();
        }
    }
}
