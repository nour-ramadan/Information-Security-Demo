/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package GUI;

import client.Client;
import crypto.AES;
import crypto.RSA;
import crypto.SSLCertificate;
import crypto.Signature;
import helper.DB;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.concurrent.TimeUnit;
import javax.swing.JFrame;
import javax.swing.SwingConstants;

/**
 *
 * @author Nour Eddin
 */
public class User extends javax.swing.JFrame {

    /**
     * Creates new form User
     */
    
    private Client client;
    private SSLCertificate clientSSLCert;
    
    public User() {
        initComponents();
    }
    
    public User(String name){
        initComponents();
        setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
        
        try {
            this.client = new Client(name);
            this.setTitle(name);

            Runnable clientRunnable;
            clientRunnable = new Runnable() {
                
                DataInputStream dataInStream = new DataInputStream(client.getSocket().getInputStream());
                DataOutputStream dataOutStream = new DataOutputStream(client.getSocket().getOutputStream());

                private void getAllUsers() throws Exception {

                    int count = dataInStream.readInt();
                    for (int i = 0, j = 0; i < count; i++) {
                        String cName = dataInStream.readUTF();
                        if (cName == null ? name != null : !cName.equals(name)) {
                            jTable1.setValueAt(cName, j++, 0);
                        }
                    }
                }
                
                private void receiveMessage() throws Exception{
        
                    String senderName = dataInStream.readUTF();
                    String msg = dataInStream.readUTF();
                    
                    recvMsgTxt.setText(recvMsgTxt.getText() + "\n" + senderName + ": " + msg);
                }
                
                private void receiveMessageEcryptedWithAES() throws Exception{
                    
                    String senderName = dataInStream.readUTF();
                    String salt = dataInStream.readUTF();
                    int msgLen = dataInStream.readInt();
                    byte[] encryptedMessage = new byte[msgLen];
                    dataInStream.read(encryptedMessage);
                    
                    String secretKey = AES.generateKey(1, 0, salt);
                    String msg = AES.decrypt(encryptedMessage, AES.stringToSecretKey(secretKey));
                    
                    recvMsgTxt.setText(recvMsgTxt.getText() + "\n" + "AES " + senderName + ": " + msg);
                }
                
                private void receiveMessageEncryptedWithRSA() throws Exception{
                    
                    String senderName = dataInStream.readUTF();
                    int msgLen = dataInStream.readInt();
                    byte[] encryptedMessage = new byte[msgLen];
                    dataInStream.read(encryptedMessage);
                    
                    String msg = RSA.decrypt(encryptedMessage, client.getKeyPair().getPrivate());
                    
                    recvMsgTxt.setText(recvMsgTxt.getText() + "\n" + "RSA " + senderName + ": " + msg);
                }
               
                public void receiveMessageEncryptedWithPGBandSignture() throws Exception {

                    String senderName = dataInStream.readUTF();
                    int encryptedMsgLen = dataInStream.readInt();
                    int encryptedSecretKeyLen = dataInStream.readInt();
                    int signedHashLen = dataInStream.readInt();
                    byte[] msg = new byte[encryptedMsgLen + encryptedSecretKeyLen + signedHashLen];
                    dataInStream.read(msg);

                    byte[] encryptedMessage;
                    byte[] encryptedSecretKey;
                    byte[] signedHash;
                    
                    encryptedMessage = Arrays.copyOfRange(msg, 0, encryptedMsgLen);
                    encryptedSecretKey = Arrays.copyOfRange(msg, encryptedMsgLen, encryptedMsgLen + encryptedSecretKeyLen);
                    signedHash = Arrays.copyOfRange(msg, encryptedMsgLen + encryptedSecretKeyLen, encryptedMsgLen + encryptedSecretKeyLen + signedHashLen);
                    
                    String secretKey = RSA.decrypt(encryptedSecretKey, client.getKeyPair().getPrivate());
                    String message = AES.decrypt(encryptedMessage, AES.stringToSecretKey(secretKey));
                    
                    // verify the consistency of the message by checking the hashes
                    
                    byte[] newHash = Signature.getHash(message.getBytes());
                    byte[] oldHash = Signature.un_sign(signedHash, DB.decodePublicKey(DB.getEncodedUserPublicKey(senderName)));
                    
                    if(!Arrays.equals(newHash, oldHash)){
                        System.out.println("The connection is comporomised! abort do not receive");
                    }
                    
                    recvMsgTxt.setText(recvMsgTxt.getText() + "\n" + "PGB " + senderName + ": " + message);
                }
                
                private void getClientCertificate() throws Exception{
                    
                    String senderName = dataInStream.readUTF();
                    
                    dataOutStream.writeInt(3010);
                    dataOutStream.writeUTF(senderName);
                    
                    ObjectOutputStream objectOut = new ObjectOutputStream(client.getSocket().getOutputStream());
                    
                    objectOut.writeObject(client.getSSLCert());
                    
//                    objectOut.close();
                }
                
                private void getClientCertificate_2() throws Exception{
                    
                    int x = dataInStream.readInt();

                    ObjectInputStream objectIn = new ObjectInputStream(client.getSocket().getInputStream());
                    
                    clientSSLCert = (SSLCertificate)objectIn.readObject();
                    
//                    objectIn.close();
                }

                @Override
                public void run() {

                    System.out.println("Client receiving thread started.");

                    while (true) {

                        try {

                            int type = this.dataInStream.readInt();

                            if (type == 2) {

                                getAllUsers();
                            }
                            else if(type == 3){
                                
                                receiveMessage();
                            }
                            else if(type == 4){
                                
                                receiveMessageEcryptedWithAES();
                            }
                            else if(type == 1000){
                                
                                receiveMessageEncryptedWithRSA();
                            }
                            else if(type == 2000){
                                
                                receiveMessageEncryptedWithPGBandSignture();
                            }
                            else if(type == 3000){
                                
                                getClientCertificate();
                            }
                            else if(type == 3010){
                                
                                getClientCertificate_2();
                            }

                        } catch (Exception ex) {
                            System.out.println(ex.getMessage());
                        }
                    }
                }
            };
            
            new Thread(clientRunnable).start();
            
        } catch (Exception ex) {
        }
    }

    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jLabel1 = new javax.swing.JLabel();
        refreshUsersBtn = new javax.swing.JButton();
        sendMsgTxt = new javax.swing.JTextField();
        sendMsgBtn = new javax.swing.JButton();
        jSeparator1 = new javax.swing.JSeparator();
        jLabel2 = new javax.swing.JLabel();
        jSeparator2 = new javax.swing.JSeparator();
        jLabel3 = new javax.swing.JLabel();
        jLabel4 = new javax.swing.JLabel();
        jScrollPane1 = new javax.swing.JScrollPane();
        jTable1 = new javax.swing.JTable();
        getSSLCert = new javax.swing.JButton();
        validateSSLBtn = new javax.swing.JButton();
        jSeparator3 = new javax.swing.JSeparator();
        jLabel5 = new javax.swing.JLabel();
        validateSSLtxt = new javax.swing.JTextField();
        broadcastBtn = new javax.swing.JButton();
        encryptTypeCmb = new javax.swing.JComboBox();
        jScrollPane2 = new javax.swing.JScrollPane();
        SSLtxt = new javax.swing.JTextArea();
        jScrollPane3 = new javax.swing.JScrollPane();
        recvMsgTxt = new javax.swing.JTextArea();
        jButton1 = new javax.swing.JButton();

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);

        jLabel1.setText("Online users");

        refreshUsersBtn.setText("Refresh");
        refreshUsersBtn.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                refreshUsersBtnActionPerformed(evt);
            }
        });

        sendMsgBtn.setText("Send");
        sendMsgBtn.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                sendMsgBtnActionPerformed(evt);
            }
        });

        jSeparator1.setOrientation(javax.swing.SwingConstants.VERTICAL);

        jLabel2.setText("Send messages");

        jLabel4.setText("Receive messages");

        jTable1.setModel(new javax.swing.table.DefaultTableModel(
            new Object [][] {
                {null},
                {null},
                {null},
                {null},
                {null},
                {null},
                {null},
                {null},
                {null},
                {null},
                {null},
                {null},
                {null},
                {null},
                {null},
                {null},
                {null},
                {null}
            },
            new String [] {
                "Title 1"
            }
        ));
        jTable1.setRequestFocusEnabled(false);
        jScrollPane1.setViewportView(jTable1);

        getSSLCert.setText("Renew SSL");
        getSSLCert.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                getSSLCertActionPerformed(evt);
            }
        });

        validateSSLBtn.setText("Validate");
        validateSSLBtn.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                validateSSLBtnActionPerformed(evt);
            }
        });

        jSeparator3.setOrientation(javax.swing.SwingConstants.VERTICAL);

        jLabel5.setText("SSL");

        broadcastBtn.setText("Broadcast");
        broadcastBtn.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                broadcastBtnActionPerformed(evt);
            }
        });

        encryptTypeCmb.setModel(new javax.swing.DefaultComboBoxModel(new String[] { "Plain Text", "AES", "RSA", "PGB" }));

        SSLtxt.setEditable(false);
        SSLtxt.setColumns(20);
        SSLtxt.setRows(5);
        SSLtxt.setText("NO SSL");
        jScrollPane2.setViewportView(SSLtxt);

        recvMsgTxt.setEditable(false);
        recvMsgTxt.setColumns(20);
        recvMsgTxt.setRows(5);
        jScrollPane3.setViewportView(recvMsgTxt);

        jButton1.setText("New Pair");
        jButton1.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton1ActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createSequentialGroup()
                        .addGap(44, 44, 44)
                        .addComponent(jLabel1))
                    .addGroup(layout.createSequentialGroup()
                        .addGap(22, 22, 22)
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                            .addComponent(jScrollPane1, javax.swing.GroupLayout.PREFERRED_SIZE, 0, Short.MAX_VALUE)
                            .addComponent(refreshUsersBtn, javax.swing.GroupLayout.DEFAULT_SIZE, 121, Short.MAX_VALUE))))
                .addGap(31, 31, 31)
                .addComponent(jSeparator1, javax.swing.GroupLayout.PREFERRED_SIZE, 18, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                        .addGroup(layout.createSequentialGroup()
                            .addGap(178, 178, 178)
                            .addComponent(jLabel2))
                        .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                            .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                            .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                .addComponent(jScrollPane3, javax.swing.GroupLayout.PREFERRED_SIZE, 415, javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addComponent(jSeparator2, javax.swing.GroupLayout.PREFERRED_SIZE, 415, javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addGroup(layout.createSequentialGroup()
                                    .addGap(5, 5, 5)
                                    .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                        .addGroup(layout.createSequentialGroup()
                                            .addComponent(sendMsgBtn, javax.swing.GroupLayout.PREFERRED_SIZE, 201, javax.swing.GroupLayout.PREFERRED_SIZE)
                                            .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                            .addComponent(broadcastBtn, javax.swing.GroupLayout.PREFERRED_SIZE, 202, javax.swing.GroupLayout.PREFERRED_SIZE))
                                        .addGroup(layout.createSequentialGroup()
                                            .addComponent(encryptTypeCmb, javax.swing.GroupLayout.PREFERRED_SIZE, 92, javax.swing.GroupLayout.PREFERRED_SIZE)
                                            .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                            .addComponent(sendMsgTxt, javax.swing.GroupLayout.PREFERRED_SIZE, 311, javax.swing.GroupLayout.PREFERRED_SIZE)))))))
                    .addGroup(layout.createSequentialGroup()
                        .addGap(177, 177, 177)
                        .addComponent(jLabel4)))
                .addGap(33, 33, 33)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(jSeparator3, javax.swing.GroupLayout.PREFERRED_SIZE, 12, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addGroup(layout.createSequentialGroup()
                                .addGap(102, 102, 102)
                                .addComponent(jLabel5))
                            .addGroup(layout.createSequentialGroup()
                                .addGap(18, 18, 18)
                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                    .addGroup(layout.createSequentialGroup()
                                        .addComponent(getSSLCert, javax.swing.GroupLayout.PREFERRED_SIZE, 109, javax.swing.GroupLayout.PREFERRED_SIZE)
                                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                        .addComponent(jButton1, javax.swing.GroupLayout.PREFERRED_SIZE, 104, javax.swing.GroupLayout.PREFERRED_SIZE))
                                    .addComponent(jScrollPane2, javax.swing.GroupLayout.PREFERRED_SIZE, 217, javax.swing.GroupLayout.PREFERRED_SIZE)))
                            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                    .addComponent(validateSSLtxt, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.PREFERRED_SIZE, 231, javax.swing.GroupLayout.PREFERRED_SIZE)
                                    .addComponent(validateSSLBtn, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.PREFERRED_SIZE, 231, javax.swing.GroupLayout.PREFERRED_SIZE))))
                        .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                        .addGap(186, 186, 186)
                        .addComponent(jLabel3)
                        .addGap(93, 93, 93))))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGap(24, 24, 24)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(jLabel1)
                        .addGap(18, 18, 18)
                        .addComponent(jScrollPane1, javax.swing.GroupLayout.PREFERRED_SIZE, 322, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addGroup(layout.createSequentialGroup()
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                .addComponent(jLabel3))
                            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                .addComponent(refreshUsersBtn))))
                    .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING, false)
                        .addComponent(jSeparator3, javax.swing.GroupLayout.Alignment.LEADING)
                        .addComponent(jSeparator1, javax.swing.GroupLayout.Alignment.LEADING)
                        .addGroup(layout.createSequentialGroup()
                            .addComponent(jLabel5)
                            .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                            .addComponent(jScrollPane2, javax.swing.GroupLayout.PREFERRED_SIZE, 206, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addGap(28, 28, 28)
                            .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                                .addComponent(getSSLCert)
                                .addComponent(jButton1))
                            .addGap(36, 36, 36)
                            .addComponent(validateSSLtxt, javax.swing.GroupLayout.PREFERRED_SIZE, 49, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                            .addComponent(validateSSLBtn))
                        .addGroup(layout.createSequentialGroup()
                            .addComponent(jLabel2)
                            .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                            .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                                .addComponent(sendMsgTxt, javax.swing.GroupLayout.PREFERRED_SIZE, 36, javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addComponent(encryptTypeCmb, javax.swing.GroupLayout.PREFERRED_SIZE, 36, javax.swing.GroupLayout.PREFERRED_SIZE))
                            .addGap(18, 18, 18)
                            .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                                .addComponent(sendMsgBtn)
                                .addComponent(broadcastBtn))
                            .addGap(18, 18, 18)
                            .addComponent(jSeparator2, javax.swing.GroupLayout.PREFERRED_SIZE, 10, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                            .addComponent(jLabel4)
                            .addGap(14, 14, 14)
                            .addComponent(jScrollPane3, javax.swing.GroupLayout.PREFERRED_SIZE, 233, javax.swing.GroupLayout.PREFERRED_SIZE))))
                .addContainerGap(43, Short.MAX_VALUE))
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents

    private void refreshUsersBtnActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_refreshUsersBtnActionPerformed
        try {
            // TODO add your handling code here:
            client.getAllUsers();
        } catch (Exception ex) {}
    }//GEN-LAST:event_refreshUsersBtnActionPerformed

    private void sendMsgBtnActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_sendMsgBtnActionPerformed
        // TODO add your handling code here:
        ArrayList<String> receivers = new ArrayList<>();
        int[] rows = jTable1.getSelectedRows();
        for(int i = 0; i < rows.length; i++){
            receivers.add((String)jTable1.getValueAt(rows[i], 0));
        }
        
        try{
            int type = getEncryptType();
            for(String receiver : receivers){
                System.out.println(receiver);
                if(type == 0)
                    client.sendMessage(sendMsgTxt.getText(), receiver);
                else if(type == 1)
                    client.sendMessageEncryptedWithAES(sendMsgTxt.getText(), receiver);
                else if(type == 2)
                    client.sendMessageEncryptedWithRSA(sendMsgTxt.getText(), receiver);
                else 
                    client.sendMessageEncryptedWithPGBandSignture(sendMsgTxt.getText(), receiver);
            }
        }catch(Exception ex){}
    }//GEN-LAST:event_sendMsgBtnActionPerformed

    private void getSSLCertActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_getSSLCertActionPerformed
        // TODO add your handling code here:
        try{
            client.setSSLCert(client.getSSLCertificate());
            System.out.println(client.getSSLCert().toString());
            SSLtxt.setText(client.getSSLCert().toString());
            
        }catch(Exception ex){System.err.println(ex.getMessage());}
    }//GEN-LAST:event_getSSLCertActionPerformed

    private void broadcastBtnActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_broadcastBtnActionPerformed
        // TODO add your handling code here:
        ArrayList<String> receivers = new ArrayList<>();
        int count = jTable1.getRowCount();
        for(int i = 0; i < count; i++){
            if(jTable1.getValueAt(i, 0) == null) break;
            receivers.add((String)jTable1.getValueAt(i, 0));
        }
        
        try{
            int type = getEncryptType();
            for(String receiver : receivers){
                System.out.println(receiver);
                if(type == 0)
                    client.sendMessage(sendMsgTxt.getText(), receiver);
                else if(type == 1)
                    client.sendMessageEncryptedWithAES(sendMsgTxt.getText(), receiver);
                else if(type == 2)
                    client.sendMessageEncryptedWithRSA(sendMsgTxt.getText(), receiver);
                else 
                    client.sendMessageEncryptedWithPGBandSignture(sendMsgTxt.getText(), receiver);
            }
        }catch(Exception ex){}
    }//GEN-LAST:event_broadcastBtnActionPerformed

    private void validateSSLBtnActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_validateSSLBtnActionPerformed
        // TODO add your handling code here:
        String cell = (String)jTable1.getValueAt(jTable1.getSelectedRow(),0);
        System.out.println(cell);
        try{
            client.getClientSSLCertificate(cell);
            TimeUnit.SECONDS.sleep(2);
            if(!clientSSLCert.getExisted()){
                validateSSLtxt.setText("Client " + cell + " doesn't have an SSL certificate");
            }
            else if(client.validateSSLCertificate(clientSSLCert)){
                validateSSLtxt.setText("Client " + cell + "'s certificate has been validated successfully");
            }
            else{
                validateSSLtxt.setText("Couldn't verify client " + cell + "'s certificate, it might be compromised!! be alerted");
            }
        }catch(Exception ex){System.err.println(ex.getMessage());}
    }//GEN-LAST:event_validateSSLBtnActionPerformed

    private void jButton1ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton1ActionPerformed
        // TODO add your handling code here:
        try{
            client.generateNewPair();
        }catch(Exception ex){}
    }//GEN-LAST:event_jButton1ActionPerformed

    /**
     * @param args the command line arguments
     */
    public static void main(String args[]) {
        /* Set the Nimbus look and feel */
        //<editor-fold defaultstate="collapsed" desc=" Look and feel setting code (optional) ">
        /* If Nimbus (introduced in Java SE 6) is not available, stay with the default look and feel.
         * For details see http://download.oracle.com/javase/tutorial/uiswing/lookandfeel/plaf.html 
         */
        try {
            for (javax.swing.UIManager.LookAndFeelInfo info : javax.swing.UIManager.getInstalledLookAndFeels()) {
                if ("Nimbus".equals(info.getName())) {
                    javax.swing.UIManager.setLookAndFeel(info.getClassName());
                    break;
                }
            }
        } catch (ClassNotFoundException ex) {
            java.util.logging.Logger.getLogger(User.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (InstantiationException ex) {
            java.util.logging.Logger.getLogger(User.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (IllegalAccessException ex) {
            java.util.logging.Logger.getLogger(User.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (javax.swing.UnsupportedLookAndFeelException ex) {
            java.util.logging.Logger.getLogger(User.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        }
        //</editor-fold>

        /* Create and display the form */
        java.awt.EventQueue.invokeLater(new Runnable() {
            public void run() {
                new User().setVisible(true);
            }
        });
    }

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JTextArea SSLtxt;
    private javax.swing.JButton broadcastBtn;
    private javax.swing.JComboBox encryptTypeCmb;
    private javax.swing.JButton getSSLCert;
    private javax.swing.JButton jButton1;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JLabel jLabel4;
    private javax.swing.JLabel jLabel5;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JScrollPane jScrollPane2;
    private javax.swing.JScrollPane jScrollPane3;
    private javax.swing.JSeparator jSeparator1;
    private javax.swing.JSeparator jSeparator2;
    private javax.swing.JSeparator jSeparator3;
    private javax.swing.JTable jTable1;
    private javax.swing.JTextArea recvMsgTxt;
    private javax.swing.JButton refreshUsersBtn;
    private javax.swing.JButton sendMsgBtn;
    private javax.swing.JTextField sendMsgTxt;
    private javax.swing.JButton validateSSLBtn;
    private javax.swing.JTextField validateSSLtxt;
    // End of variables declaration//GEN-END:variables
    
    private int getEncryptType(){
        return encryptTypeCmb.getSelectedIndex();
    }
}