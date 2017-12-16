/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package crypto;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
import javax.crypto.Cipher;

/**
 *
 * @author Nour Eddin
 */
public class RSA {
    
    private static Cipher cipher = null;
    
    public static byte[] encrypt(byte[] data, PublicKey publicKey) throws Exception {

        cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] cipherText = cipher.doFinal(data);
//        String result = new String(cipherText);

        return cipherText;
    }

    public static String decrypt(byte[] data, PrivateKey privateKey) throws Exception {

        cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedText = cipher.doFinal(data);
        String result = new String(decryptedText);
        
        return result;
    }
    
    public static String SSLSign(String data, PrivateKey privateKey) throws Exception {

        cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);
        byte[] cipherText = cipher.doFinal(data.getBytes());
        cipherText = Base64.getEncoder().encode(cipherText);
        String result = new String(cipherText);
        return result;
    }
    
    public static String SSL_unsign(String data, PublicKey publicKey) throws Exception {

        cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, publicKey);
        byte[] text = cipher.doFinal(Base64.getDecoder().decode(data));
        String result = new String(text);
        return result;
    }
}
