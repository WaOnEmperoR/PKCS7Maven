/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package id.go.bppt.ptik.pkcs7maven.ui;

import id.go.bppt.ptik.pkcs7maven.controller.SignatureController;
import id.go.bppt.ptik.pkcs7maven.utils.FileHelper;
import id.go.bppt.ptik.pkcs7maven.utils.PrivateKey_CertChain;
import id.go.bppt.ptik.pkcs7maven.utils.StringFormatException;
import id.go.bppt.ptik.pkcs7maven.utils.UnmatchedSignatureException;
import java.awt.Color;
import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintStream;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.text.ParseException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.JFileChooser;
import javax.swing.JTextArea;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.filechooser.FileSystemView;
import org.apache.commons.io.FilenameUtils;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.util.encoders.Hex;

/**
 *
 * @author Rachmawan
 */
public class SignAndVerifySignature extends javax.swing.JFrame {

    /**
     * Creates new form SignAndVerifySignature
     */
    private PrintStream standardOut;
    
    public SignAndVerifySignature() {
        initComponents();
        
        this.setTitle("PKCS7 Signed Data Demo");
    }

    public class CustomOutputStream extends OutputStream {

        private final JTextArea textArea;

        public CustomOutputStream(JTextArea textArea) {
            this.textArea = textArea;
        }

        @Override
        public void write(int b) throws IOException {
            // redirects data to the text area
            textArea.append(String.valueOf((char) b));
            // scrolls the text area to the end of data
            textArea.setCaretPosition(textArea.getDocument().getLength());
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

        panelGroup = new javax.swing.JTabbedPane();
        panelSigning = new javax.swing.JPanel();
        txtFileInput = new javax.swing.JTextField();
        jLabel1 = new javax.swing.JLabel();
        btnFileSearch = new javax.swing.JButton();
        txtDigitalCertificate = new javax.swing.JTextField();
        jLabel2 = new javax.swing.JLabel();
        btnBrowseP12 = new javax.swing.JButton();
        passphraseField = new javax.swing.JPasswordField();
        jLabel3 = new javax.swing.JLabel();
        btnGenerateCMS = new javax.swing.JButton();
        jScrollPane1 = new javax.swing.JScrollPane();
        txtAreaLog_Signing = new javax.swing.JTextArea();
        panelVerify = new javax.swing.JPanel();
        txtSignedFile = new javax.swing.JTextField();
        jLabel4 = new javax.swing.JLabel();
        jLabel5 = new javax.swing.JLabel();
        txtOriginalFile = new javax.swing.JTextField();
        btnBrowseDER = new javax.swing.JButton();
        btnBrowseOri = new javax.swing.JButton();
        btnVerify = new javax.swing.JButton();
        jScrollPane2 = new javax.swing.JScrollPane();
        txtAreaLog_Verify = new javax.swing.JTextArea();
        txtRootCert = new javax.swing.JTextField();
        btnBrowseRoot = new javax.swing.JButton();
        jLabel6 = new javax.swing.JLabel();
        txtStatus = new javax.swing.JTextField();
        jButton1 = new javax.swing.JButton();

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);

        panelGroup.setName("TabbedPanel"); // NOI18N

        txtFileInput.setEditable(false);
        txtFileInput.setName(""); // NOI18N

        jLabel1.setText("File to be Signed");

        btnFileSearch.setText("Browse");
        btnFileSearch.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnFileSearchActionPerformed(evt);
            }
        });

        txtDigitalCertificate.setEditable(false);

        jLabel2.setText("Digital Certificate");

        btnBrowseP12.setText("Browse");
        btnBrowseP12.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnBrowseP12ActionPerformed(evt);
            }
        });

        jLabel3.setText("Passphrase");

        btnGenerateCMS.setText("Generate PKCS7 ");
        btnGenerateCMS.setToolTipText("");
        btnGenerateCMS.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnGenerateCMSActionPerformed(evt);
            }
        });

        txtAreaLog_Signing.setColumns(20);
        txtAreaLog_Signing.setRows(5);
        txtAreaLog_Signing.setEnabled(false);
        jScrollPane1.setViewportView(txtAreaLog_Signing);

        javax.swing.GroupLayout panelSigningLayout = new javax.swing.GroupLayout(panelSigning);
        panelSigning.setLayout(panelSigningLayout);
        panelSigningLayout.setHorizontalGroup(
            panelSigningLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, panelSigningLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(panelSigningLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                    .addComponent(jScrollPane1)
                    .addGroup(panelSigningLayout.createSequentialGroup()
                        .addGroup(panelSigningLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(jLabel1)
                            .addComponent(jLabel2)
                            .addComponent(jLabel3))
                        .addGap(93, 93, 93)
                        .addGroup(panelSigningLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(btnGenerateCMS, javax.swing.GroupLayout.DEFAULT_SIZE, 320, Short.MAX_VALUE)
                            .addComponent(passphraseField)
                            .addComponent(txtDigitalCertificate)
                            .addComponent(txtFileInput))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addGroup(panelSigningLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                            .addComponent(btnBrowseP12, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                            .addComponent(btnFileSearch, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))))
                .addGap(16, 16, 16))
        );
        panelSigningLayout.setVerticalGroup(
            panelSigningLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(panelSigningLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(panelSigningLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(txtFileInput, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jLabel1)
                    .addComponent(btnFileSearch))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(panelSigningLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(txtDigitalCertificate, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jLabel2)
                    .addComponent(btnBrowseP12))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(panelSigningLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(passphraseField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jLabel3))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(btnGenerateCMS)
                .addGap(18, 18, 18)
                .addComponent(jScrollPane1, javax.swing.GroupLayout.DEFAULT_SIZE, 239, Short.MAX_VALUE)
                .addContainerGap())
        );

        panelGroup.addTab("Signing", panelSigning);

        panelVerify.setName("Verify"); // NOI18N

        txtSignedFile.setEditable(false);

        jLabel4.setText("Signature File");

        jLabel5.setText("Original File");

        txtOriginalFile.setEditable(false);

        btnBrowseDER.setText("Browse");
        btnBrowseDER.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnBrowseDERActionPerformed(evt);
            }
        });

        btnBrowseOri.setText("Browse");
        btnBrowseOri.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnBrowseOriActionPerformed(evt);
            }
        });

        btnVerify.setLabel("Verify");
        btnVerify.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnVerifyActionPerformed(evt);
            }
        });

        txtAreaLog_Verify.setColumns(20);
        txtAreaLog_Verify.setRows(5);
        txtAreaLog_Verify.setEnabled(false);
        jScrollPane2.setViewportView(txtAreaLog_Verify);

        txtRootCert.setEditable(false);

        btnBrowseRoot.setText("Browse");
        btnBrowseRoot.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnBrowseRootActionPerformed(evt);
            }
        });

        jLabel6.setText("Root Cert");

        txtStatus.setEditable(false);
        txtStatus.setHorizontalAlignment(javax.swing.JTextField.CENTER);
        txtStatus.setText("STATUS");

        jButton1.setText("jButton1");
        jButton1.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton1ActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout panelVerifyLayout = new javax.swing.GroupLayout(panelVerify);
        panelVerify.setLayout(panelVerifyLayout);
        panelVerifyLayout.setHorizontalGroup(
            panelVerifyLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(panelVerifyLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(panelVerifyLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jScrollPane2, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.DEFAULT_SIZE, 574, Short.MAX_VALUE)
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, panelVerifyLayout.createSequentialGroup()
                        .addGap(0, 0, Short.MAX_VALUE)
                        .addGroup(panelVerifyLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(jLabel5)
                            .addComponent(jLabel4)
                            .addComponent(jLabel6)
                            .addComponent(jButton1))
                        .addGap(89, 89, 89)
                        .addGroup(panelVerifyLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                            .addComponent(btnVerify, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                            .addComponent(txtSignedFile)
                            .addComponent(txtOriginalFile)
                            .addComponent(txtRootCert, javax.swing.GroupLayout.PREFERRED_SIZE, 325, javax.swing.GroupLayout.PREFERRED_SIZE))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addGroup(panelVerifyLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                            .addComponent(btnBrowseDER, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                            .addComponent(btnBrowseRoot, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                            .addComponent(btnBrowseOri, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)))
                    .addComponent(txtStatus))
                .addContainerGap())
        );
        panelVerifyLayout.setVerticalGroup(
            panelVerifyLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(panelVerifyLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(panelVerifyLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(txtSignedFile, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jLabel4)
                    .addComponent(btnBrowseDER))
                .addGap(7, 7, 7)
                .addGroup(panelVerifyLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(txtOriginalFile, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(btnBrowseOri)
                    .addComponent(jLabel5))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(panelVerifyLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jLabel6)
                    .addComponent(btnBrowseRoot)
                    .addGroup(panelVerifyLayout.createSequentialGroup()
                        .addComponent(txtRootCert, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addGroup(panelVerifyLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                            .addComponent(btnVerify)
                            .addComponent(jButton1))))
                .addGap(9, 9, 9)
                .addComponent(jScrollPane2, javax.swing.GroupLayout.DEFAULT_SIZE, 216, Short.MAX_VALUE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(txtStatus, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap())
        );

        panelGroup.addTab("Verify", panelVerify);

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(panelGroup)
                .addContainerGap())
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(panelGroup)
                .addContainerGap())
        );

        panelGroup.getAccessibleContext().setAccessibleName("Signing");

        pack();
    }// </editor-fold>//GEN-END:initComponents

    private void btnFileSearchActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnFileSearchActionPerformed
        // TODO add your handling code here:
        JFileChooser jfc = new JFileChooser(FileSystemView.getFileSystemView().getHomeDirectory());
        jfc.addChoosableFileFilter(new FileNameExtensionFilter("Images", "jpg", "png", "gif", "bmp"));

        int returnValue = jfc.showOpenDialog(null);

        if (returnValue == JFileChooser.APPROVE_OPTION) {
            File selectedFile = jfc.getSelectedFile();

            txtFileInput.setText(selectedFile.getAbsolutePath());
        }
    }//GEN-LAST:event_btnFileSearchActionPerformed

    private void btnBrowseP12ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnBrowseP12ActionPerformed
        // TODO add your handling code here:
        JFileChooser jfc = new JFileChooser(FileSystemView.getFileSystemView().getHomeDirectory());
        jfc.addChoosableFileFilter(new FileNameExtensionFilter("P12 Files", "p12"));

        int returnValue = jfc.showOpenDialog(null);

        if (returnValue == JFileChooser.APPROVE_OPTION) {
            File selectedFile = jfc.getSelectedFile();

            txtDigitalCertificate.setText(selectedFile.getAbsolutePath());
        }
    }//GEN-LAST:event_btnBrowseP12ActionPerformed

    private void btnGenerateCMSActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnGenerateCMSActionPerformed
        // TODO add your handling code here:
        PrintStream printStream = new PrintStream(new CustomOutputStream(txtAreaLog_Signing));

        // keeps reference of standard output stream
        standardOut = System.out;

        // re-assigns standard output stream and error output stream
        System.setOut(printStream);
        System.setErr(printStream);
        
        String p12_file = txtDigitalCertificate.getText();
        String file_to_sign = txtFileInput.getText();
        String passphrase = passphraseField.getText();
        
        String outfile = FilenameUtils.removeExtension(file_to_sign) + ".DER";
        
        System.out.format("%-32s%s\n", "TARGET FILE", outfile);
        
        try {
            PrivateKey_CertChain pkcc = new PrivateKey_CertChain(p12_file, passphrase, "PKCS12");
            
            System.out.println("***SIGNING***");
            
            byte[] img_byte_rep = FileHelper.BitmapToByteArray(file_to_sign);
            MessageDigest digest01 = MessageDigest.getInstance("SHA-256");
            byte[] input_rep = img_byte_rep;
            byte[] myhash = digest01.digest(input_rep);
            String hash_str_rep = Hex.toHexString(myhash);
            System.out.format("%-32s%s\n", "Digest of Content", hash_str_rep);
        
            SignatureController cms_control = new SignatureController();
            CMSSignedData my_cms = cms_control.CMSGenerator(input_rep, pkcc);
            
            byte[] cms_byte_rep = my_cms.getEncoded();
            byte[] cms_DER_rep = FileHelper.CMStoDER(my_cms);
            FileHelper.binaryFileWriter(outfile, cms_DER_rep);
        } catch (KeyStoreException | UnrecoverableKeyException | NoSuchAlgorithmException | IOException ex) {
            Logger.getLogger(SignAndVerifySignature.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        System.out.println("***END OF SIGNING***");
    }//GEN-LAST:event_btnGenerateCMSActionPerformed

    private void btnBrowseDERActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnBrowseDERActionPerformed
        // TODO add your handling code here:
        JFileChooser jfc = new JFileChooser(FileSystemView.getFileSystemView().getHomeDirectory());
        jfc.addChoosableFileFilter(new FileNameExtensionFilter("DER Files", "der"));

        int returnValue = jfc.showOpenDialog(null);

        if (returnValue == JFileChooser.APPROVE_OPTION) {
            File selectedFile = jfc.getSelectedFile();

            txtSignedFile.setText(selectedFile.getAbsolutePath());
        }
    }//GEN-LAST:event_btnBrowseDERActionPerformed

    private void btnBrowseOriActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnBrowseOriActionPerformed
        // TODO add your handling code here:
        JFileChooser jfc = new JFileChooser(FileSystemView.getFileSystemView().getHomeDirectory());
        jfc.addChoosableFileFilter(new FileNameExtensionFilter("Images", "jpg", "png", "gif", "bmp"));

        int returnValue = jfc.showOpenDialog(null);

        if (returnValue == JFileChooser.APPROVE_OPTION) {
            File selectedFile = jfc.getSelectedFile();

            txtOriginalFile.setText(selectedFile.getAbsolutePath());
        }
    }//GEN-LAST:event_btnBrowseOriActionPerformed

    private void btnBrowseRootActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnBrowseRootActionPerformed
        // TODO add your handling code here:
        JFileChooser jfc = new JFileChooser(FileSystemView.getFileSystemView().getHomeDirectory());
        jfc.addChoosableFileFilter(new FileNameExtensionFilter("Certificate", "cer"));

        int returnValue = jfc.showOpenDialog(null);

        if (returnValue == JFileChooser.APPROVE_OPTION) {
            File selectedFile = jfc.getSelectedFile();

            txtRootCert.setText(selectedFile.getAbsolutePath());
        }
    }//GEN-LAST:event_btnBrowseRootActionPerformed

    private void btnVerifyActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnVerifyActionPerformed
        // TODO add your handling code here:
        PrintStream printStream = new PrintStream(new CustomOutputStream(txtAreaLog_Verify));

        // keeps reference of standard output stream
        standardOut = System.out;

        // re-assigns standard output stream and error output stream
        System.setOut(printStream);
        System.setErr(printStream);
        
        System.out.println("***VERIFICATION***");
        
        String signed_file = txtSignedFile.getText();
        String original_file = txtOriginalFile.getText();
        String root_cert_file = txtRootCert.getText();
        
        SignatureController cms_control = new SignatureController();
        cms_control.setRoot_cert_path(root_cert_file);
        
        byte[] img_byte_rep = FileHelper.BitmapToByteArray(original_file);
        
        try {
            byte[] cms_from_file = FileHelper.binaryFileReader(signed_file);
            CMSSignedData cms_obj = new CMSSignedData(cms_from_file);
            
            int result = cms_control.VerifyCMS(img_byte_rep, cms_from_file);
            if (result>0)
            {
                txtStatus.setText("SIGNATURE VERIFIED");
                txtStatus.setBackground(Color.GREEN);
            }
            else
            {
                txtStatus.setText("SIGNATURE VERIFICATION FAILED");
                txtStatus.setBackground(Color.RED);
            }
        } catch (IOException | CMSException | UnmatchedSignatureException ex) {
            Logger.getLogger(SignAndVerifySignature.class.getName()).log(Level.SEVERE, null, ex);
            txtStatus.setText("SIGNATURE VERIFICATION FAILED");
            txtStatus.setBackground(Color.RED);
        } catch (StringFormatException | ParseException ex) {
            Logger.getLogger(SignAndVerifySignature.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        System.out.println("***END OF VERIFICATION***");
    }//GEN-LAST:event_btnVerifyActionPerformed

    private void jButton1ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton1ActionPerformed
        // TODO add your handling code here:
        VerifySample();
    }//GEN-LAST:event_jButton1ActionPerformed

    
    private void VerifySample()
    {
        SignatureController cms_control = new SignatureController();
        cms_control.setRoot_cert_path("D:\\Tugas PTIK\\Certificate Authority\\E-voting\\Real_Root_CA.cer");
        
        byte[] cms_from_file;
        try {
            cms_from_file = FileHelper.binaryFileReader("D:\\Tugas PTIK\\Pemilu Elektronik\\evm2017_67208a11-0c76-4078-9284-806347c0932c.DER");
            CMSSignedData cms_obj = new CMSSignedData(cms_from_file);
            
//            int result = cms_control.verifyCMSNotDetached(cms_from_file);
//            if (result>0)
//            {
//                txtStatus.setText("SIGNATURE VERIFIED");
//                txtStatus.setBackground(Color.GREEN);
//            }
//            else
//            {
//                txtStatus.setText("SIGNATURE VERIFICATION FAILED");
//                txtStatus.setBackground(Color.RED);
//            }
        } catch (IOException | CMSException ex) {
            Logger.getLogger(SignAndVerifySignature.class.getName()).log(Level.SEVERE, null, ex);
        }
        
    }
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
            java.util.logging.Logger.getLogger(SignAndVerifySignature.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (InstantiationException ex) {
            java.util.logging.Logger.getLogger(SignAndVerifySignature.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (IllegalAccessException ex) {
            java.util.logging.Logger.getLogger(SignAndVerifySignature.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (javax.swing.UnsupportedLookAndFeelException ex) {
            java.util.logging.Logger.getLogger(SignAndVerifySignature.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        }
        //</editor-fold>
        //</editor-fold>

        /* Create and display the form */
        java.awt.EventQueue.invokeLater(new Runnable() {
            public void run() {
                new SignAndVerifySignature().setVisible(true);
            }
        });
    }

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton btnBrowseDER;
    private javax.swing.JButton btnBrowseOri;
    private javax.swing.JButton btnBrowseP12;
    private javax.swing.JButton btnBrowseRoot;
    private javax.swing.JButton btnFileSearch;
    private javax.swing.JButton btnGenerateCMS;
    private javax.swing.JButton btnVerify;
    private javax.swing.JButton jButton1;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JLabel jLabel4;
    private javax.swing.JLabel jLabel5;
    private javax.swing.JLabel jLabel6;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JScrollPane jScrollPane2;
    private javax.swing.JTabbedPane panelGroup;
    private javax.swing.JPanel panelSigning;
    private javax.swing.JPanel panelVerify;
    private javax.swing.JPasswordField passphraseField;
    private javax.swing.JTextArea txtAreaLog_Signing;
    private javax.swing.JTextArea txtAreaLog_Verify;
    private javax.swing.JTextField txtDigitalCertificate;
    private javax.swing.JTextField txtFileInput;
    private javax.swing.JTextField txtOriginalFile;
    private javax.swing.JTextField txtRootCert;
    private javax.swing.JTextField txtSignedFile;
    private javax.swing.JTextField txtStatus;
    // End of variables declaration//GEN-END:variables
}
