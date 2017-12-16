/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package crypto;

import helper.DB;
import java.io.Serializable;
import java.security.PublicKey;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;

/**
 *
 * @author Nour Eddin
 */
public class SSLCertificate implements Serializable{
    
    private final String clientName;
    private final PublicKey publicKey;
    private final Date date;
    private final String certificate;
    private final boolean existed;
    
    public SSLCertificate(){
        this.clientName = null;
        this.publicKey = null;
        this.date = null;
        this.certificate = null;
        this.existed = false;
    }
    
    public SSLCertificate(String clientName, PublicKey publicKey, String certificate){
        
        this.clientName = clientName;
        this.publicKey = publicKey;
        this.certificate = certificate;
        this.date = new Date();
        this.existed = true;
    }
    
    public String getCertificate(){
        return this.certificate;
    }
    
    public PublicKey getPublicKey(){
        return this.publicKey;
    }
    
    public boolean getExisted(){ 
        return this.existed;
    }
    
    @Override
    public String toString(){
        
        DateFormat dateFormat = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss");
        String result = "";
        
        try{
            result = "Client " + clientName + "\n";
            result += "Public Key " + DB.encodePublicKey(publicKey) + "\n";
            result += "This certificate has been signed on " + dateFormat.format(date) + "\n";
            result += "Certificate Authority Signature:\n";
            result += certificate;
            
        }catch(Exception ex){}
        
        return result;
    }
}
