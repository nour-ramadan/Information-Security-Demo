    /*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package crypto;

import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import javax.crypto.Cipher;

/**
 *
 * @author Nour Eddin
 */
public class Signature {
    
    private static MessageDigest hasher = null;
    private static Cipher cipher = null;
    
    public static byte[] getHash(byte[] data) throws Exception{
        hasher = MessageDigest.getInstance("MD5");
        return hasher.digest(data);
    }
    
    public static byte[] sign(byte[] hash, PrivateKey privateKey) throws Exception{
        cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);
        byte[] signture = cipher.doFinal(hash);
        return signture;
    }
    
    public static byte[] un_sign(byte[] signedHash, PublicKey publicKye) throws Exception{
        cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, publicKye);
        byte[] hash = cipher.doFinal(signedHash);
        return hash;
    }
}
