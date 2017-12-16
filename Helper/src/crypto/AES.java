/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package crypto;

import java.security.MessageDigest;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 * @author Nour Eddin
 */
public class AES {

    private static Cipher cipher = null;

    public static byte[] encrypt(byte[] plainTextByte, SecretKey secretKey)
            throws Exception {
        cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encryptedBytes = cipher.doFinal(plainTextByte);
//        String result = new String(encryptedBytes,"UTF-8");
        return encryptedBytes;
    }

    public static String decrypt(byte[] encryptedBytes, SecretKey secretKey)
            throws Exception {
        cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
        String result = new String(decryptedBytes,"UTF-8");
        return result;
    }
    
    public static SecretKey stringToSecretKey(String s){
        
        byte[] decodedKey = s.getBytes();
        SecretKey secretKey = new SecretKeySpec(decodedKey, "AES");
        
        return secretKey;
    }
    
    
    public static String generateKey(int step, int block, String salt) throws Exception{
        
        String key;
        String raw;
        int factor = 0;
        
        if(block==0) factor = 16;
        else if(block==1) factor = 24;
        else if(block==2) factor = 32;
        else throw new Exception("Inconsistent block size");
        
        if(step*factor + factor > 128) throw new Exception("Inconsistent step size");
        
        raw = "This would be more secure if I could connect to a webapi to fetch the raw string or"
                + "we can agree on a procedure with all parties that gives us the raw string"
                + "say, search for (Bignut in the pretty island) and the first result title is the raw string";
        
        raw += salt;
        
        key = sha512(raw);
        
        key = key.substring(step*factor, step*factor+factor);
        
        return key;
    }
    
    public static String sha512(String base) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-512");
            byte[] hash = digest.digest(base.getBytes("UTF-8"));
            StringBuffer hexString = new StringBuffer();

            for (int i = 0; i < hash.length; i++) {
                String hex = Integer.toHexString(0xff & hash[i]);
                if (hex.length() == 1) {
                    hexString.append('0');
                }
                hexString.append(hex);
            }

            return hexString.toString();
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
    }
 
}
