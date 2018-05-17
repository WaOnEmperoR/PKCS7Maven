package id.go.bppt.ptik.pkcs7maven.example;


import id.go.bppt.ptik.pkcs7maven.controller.SignatureController;
import id.go.bppt.ptik.pkcs7maven.utils.FileHelper;
import id.go.bppt.ptik.pkcs7maven.utils.PrivateKey_CertChain;
import id.go.bppt.ptik.pkcs7maven.utils.UnmatchedSignatureException;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
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
     */
    public static void main(String[] args) throws UnmatchedSignatureException {
        // TODO code application logic here
//        String path_p12 = "D:\\Tugas PTIK\\Certificate Authority\\E-voting\\mempawah\\iqbal_196909191994031004.p12";
//        String path_p12 = "D:\\Tugas PTIK\\Certificate Authority\\E-voting\\1234567890987654.p12";
        String path_p12 = "D:\\Tugas PTIK\\Pemilu Elektronik\\SIDOARJO - MARET 2018\\TPS\\eka.p12";
        String instance = "PKCS12";
        String passphrase = "rahasiaya";
       
        String img_input = "D:\\Tugas PTIK\\Certificate Authority\\SIMONEV\\Input\\IMG-20161004-WA0012.jpg";
        String outfile = "D:\\Tugas PTIK\\Pemilu Elektronik\\SIDOARJO - MARET 2018\\CMS_example.DER";
        
        // Verify against root certificate
        String root_cert_path = "D:\\Tugas PTIK\\Certificate Authority\\E-voting\\Real_Root_CA.cer";
        
        try {
            PrivateKey_CertChain pkcc = new PrivateKey_CertChain(path_p12, passphrase, instance);
           
            byte[] img_byte_rep = FileHelper.BitmapToByteArray(img_input);
            
            System.out.println("***SIGNING***");
            MessageDigest digest01 = MessageDigest.getInstance("SHA-256");
            byte[] input_rep = img_byte_rep;
//            byte[] input_rep = "halohaloTes".getBytes();
            byte[] myhash = digest01.digest(input_rep);
            String hash_str_rep = Hex.toHexString(myhash);
            System.out.format("%-32s%s\n", "Digest of Content", hash_str_rep);
        
            SignatureController cms_control = new SignatureController();
            cms_control.setRoot_cert_path(root_cert_path);
            CMSSignedData my_cms = cms_control.CMSGenerator(input_rep, pkcc);
            
            byte[] cms_byte_rep = my_cms.getEncoded();
            byte[] cms_DER_rep = FileHelper.CMStoDER(my_cms);
            FileHelper.binaryFileWriter(outfile, cms_DER_rep);
                                   
            System.out.println("***VERIFYING***");
            
            cms_control.VerifyCMS(input_rep, cms_byte_rep);
//                            
//            byte[] cms_from_file = FileHelper.binaryFileReader(outfile);
//            CMSSignedData cms_obj = new CMSSignedData(cms_from_file);
//            boolean b = cms_control.VerifyCMS(cms_obj, hash_str_rep);
//            
//            if (b)
//            {
//                System.out.println("---SIGNATURE VERIFIED---");
//                
//                System.out.println("===Fields of DN String===");
//                HashMap<String, String> hm_fields_principal = cms_control.getDN_fields();
//                for (String key : hm_fields_principal.keySet()) {
//                    String value = hm_fields_principal.get(key);
//                    System.out.println("Key = " + key + ", Value = " + value);
//                }
//                System.out.println("=========================");
//            }
//            else
//            {
//                System.out.println("---SIGNATURE VERIFICATION FAILED---");
//            }
                        
        } catch (UnrecoverableKeyException | UnsupportedEncodingException ex) {
            Logger.getLogger(DetachedSignature.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException | NoSuchAlgorithmException ex) {
            Logger.getLogger(DetachedSignature.class.getName()).log(Level.SEVERE, null, ex);
        } catch (GeneralSecurityException ex) {
            Logger.getLogger(DetachedSignature.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
}
