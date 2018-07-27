package id.go.bppt.ptik.pkcs7maven.example;


import id.go.bppt.ptik.pkcs7maven.controller.SignatureController;
import id.go.bppt.ptik.pkcs7maven.utils.FileHelper;
import id.go.bppt.ptik.pkcs7maven.utils.PrivateKey_CertChain;
import id.go.bppt.ptik.pkcs7maven.utils.StringFormatException;
import id.go.bppt.ptik.pkcs7maven.utils.UnmatchedSignatureException;
import id.go.bppt.ptik.tsa.TSAUtils;
import java.io.File;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.file.Files;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.text.ParseException;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.util.encoders.Hex;

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/**
 *
 * @author Rachmawan
 */
public class DetachedSignature {
        /**
     * @param args the command line arguments
     * @throws id.go.bppt.ptik.pkcs7maven.utils.UnmatchedSignatureException
     */
    public static void main(String[] args) throws UnmatchedSignatureException {
        // TODO code application logic here
//        String path_p12 = "D:\\Tugas PTIK\\Certificate Authority\\E-voting\\mempawah\\iqbal_196909191994031004.p12";
//        String path_p12 = "D:\\Tugas PTIK\\Certificate Authority\\E-voting\\1234567890987654.p12";
        String path_p12 = "D:\\Tugas PTIK\\Pemilu Elektronik\\SIDOARJO - MARET 2018\\TPS\\eka.p12";
        String instance = "PKCS12";
        String passphrase = "rahasiaya";
       
        String img_input = "D:\\Tugas PTIK\\Certificate Authority\\SIMONEV\\Input\\IMG-20161004-WA0012.jpg";
        String outfile = "D:\\Tugas PTIK\\Pemilu Elektronik\\SIDOARJO - MARET 2018\\CMS_example_data.p7s";
        
        // Verify against root certificate
        String root_cert_path = "D:\\Tugas PTIK\\Certificate Authority\\E-voting\\Real_Root_CA.cer";
        
        try {
            PrivateKey_CertChain pkcc = new PrivateKey_CertChain(path_p12, passphrase, instance);
           
            byte[] img_byte_rep = FileHelper.BitmapToByteArray(img_input);
            
            File fi = new File(img_input);
            byte[] fileContent = Files.readAllBytes(fi.toPath());
            
            System.out.println("***SIGNING***");
            MessageDigest digest01 = MessageDigest.getInstance("SHA-256");
//            byte[] input_rep = img_byte_rep;
            byte[] input_rep = fileContent;
            byte[] myhash = digest01.digest(input_rep);
            String hash_str_rep = Hex.toHexString(myhash);
            System.out.format("%-32s%s\n", "Digest of Content", hash_str_rep);
        
            SignatureController cms_control = new SignatureController();
            cms_control.setRoot_cert_path(root_cert_path);
            CMSSignedData my_cms = cms_control.CMSGenerator(input_rep, pkcc, true);
            
//            my_cms = TSAUtils.addTimestamp("", my_cms, 0);
            
            byte[] cms_byte_rep = my_cms.getEncoded();
            byte[] cms_DER_rep = FileHelper.CMStoDER(my_cms);
            FileHelper.binaryFileWriter(outfile, cms_DER_rep);
                                   
            System.out.println("***VERIFYING***");
            
            cms_control.VerifyCMS(input_rep, cms_byte_rep);                       
        } catch (UnrecoverableKeyException | UnsupportedEncodingException ex) {
            Logger.getLogger(DetachedSignature.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException | NoSuchAlgorithmException ex) {
            Logger.getLogger(DetachedSignature.class.getName()).log(Level.SEVERE, null, ex);
        } catch (GeneralSecurityException | StringFormatException | ParseException ex) {
            Logger.getLogger(DetachedSignature.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
}
