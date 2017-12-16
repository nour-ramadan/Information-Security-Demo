/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package ca;

import crypto.RSA;
import crypto.SSLCertificate;
import helper.DB;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;

/**
 *
 * @author Nour Eddin
 */
public class CAThread extends Thread {

    private final Socket socket;
    private final DataInputStream in;
    private final DataOutputStream outData;
    private final ObjectOutputStream out;

    public CAThread(Socket socket) throws Exception {

        this.socket = socket;
        this.in = new DataInputStream(socket.getInputStream());
        this.out = new ObjectOutputStream(socket.getOutputStream());
        this.outData = new DataOutputStream(socket.getOutputStream());
    }

    @Override
    public void run() {

        while (true) {
            try {

                int type = in.readInt();

                if (type == 1) { // get a new certificate

                    String name = in.readUTF();
                    String publicKey = in.readUTF();
                    SSLCertificate sslCert = new SSLCertificate(name, DB.decodePublicKey(publicKey), RSA.SSLSign(publicKey, CA.getKeyPair().getPrivate()));
                    out.writeObject(sslCert);
                    
                } else if (type == 2) { // get the publickey of the CA to validate the SSL
                    
                    String ss = DB.encodePublicKey(CA.getKeyPair().getPublic());
                    out.writeObject(DB.encodePublicKey(CA.getKeyPair().getPublic()));
                }

            } catch (Exception ex) {
                System.err.println(ex.getMessage());
            }
        }
    }
}
