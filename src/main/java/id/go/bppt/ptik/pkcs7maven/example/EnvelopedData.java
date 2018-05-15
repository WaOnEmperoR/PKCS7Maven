/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package id.go.bppt.ptik.pkcs7maven.example;

import id.go.bppt.ptik.pkcs7maven.controller.CipherController;
import id.go.bppt.ptik.pkcs7maven.utils.FileHelper;
import static id.go.bppt.ptik.pkcs7maven.utils.FileHelper.CMStoDER;
import static id.go.bppt.ptik.pkcs7maven.utils.FileHelper.binaryFileReader;
import id.go.bppt.ptik.pkcs7maven.utils.PrivateKey_CertChain;
import java.io.IOException;
import java.security.KeyStoreException;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.bouncycastle.cms.CMSException;

/**
 *
 * @author Rachmawan
 * Reference : http://www.baeldung.com/java-bouncy-castle
 */
public class EnvelopedData {
    
    private static final String PATH_P12_01 = "D:\\Tugas PTIK\\Pemilu Elektronik\\PEMALANG - APRIL 2018\\Pemalang - Certificate\\rsuseno.p12";
    private static final String PASSPHRASE_01 = "cobapemalang";
    private static final String INSTANCE = "PKCS12";
    
    private static final String PATH_P12_02 = "D:\\Tugas PTIK\\Pemilu Elektronik\\SIDOARJO - MARET 2018\\TPS\\ahmad.p12";
    private static final String PASSPHRASE_02 = "rahasiaya";
    
    private static final String FILE_TO_ENCRYPT = "C:\\Users\\Rachmawan\\Documents\\NetBeansProjects\\DetachedSignature\\CMS_example.DER";
    private static final String FILE_TARGET = "C:\\Users\\Rachmawan\\Documents\\NetBeansProjects\\DetachedSignature\\CMS_Encrypted_Example.DER";
    
    public static void main(String[] args)
    {
        Security.setProperty("crypto.policy", "unlimited");
        
        try {
            PrivateKey_CertChain pkcc_01 = new PrivateKey_CertChain(PATH_P12_01, PASSPHRASE_01, INSTANCE);
            PrivateKey_CertChain pkcc_02 = new PrivateKey_CertChain(PATH_P12_02, PASSPHRASE_02, INSTANCE);
            
            ArrayList<X509Certificate> list_cert = new ArrayList<>();
            
            list_cert.add(pkcc_01.getSingle_cert());
            list_cert.add(pkcc_02.getSingle_cert());
            
            String secretMessage = "Untuk menambah skalabilitas dari system OCSP yang sedang dibangun, akan ditambahkan dua buah instance server slave untuk database MySQL. Dua buah slave server ini akan ditautkan pada masing-masing instance server OCSP sehingga diharapkan mampu membagi beban pemrosesan data sertifikat yang ada agar tidak bertumpuk pada satu server. Konfigurasi yang diinginkan adalah satu server untuk write, dan dua server untuk read.  Server database master akan menyisipkan data jika ada permintaan dari EJBCA, dan menduplikasi datanya ke dua server slave. Di sini kita perlu untuk mengaktifkan jaringan untuk MySQL, dan mengikatkannya dengan IP dari server. Lebih jauh lagi, kita harus memberitahu MySQL database mana yang akan dituliskan lognya (log-log tersebut digunakan oleh slave untuk melihat perubahan apa yang ada pada master), log file yang mana yang harus digunakan olehnya, dan harus diberitahukan bahwa server MySQL ini adalah master. Konfigurasi berikutnya adalah memberikan angka unik untuk masing-masing server yang ada di grup replikasi. Untuk kemudahan, server master akan diberikan nomor satu. Terakhir, kita harus mereplikasi database ejbca, jadi kita harus memasukkan baris berikut ke file /etc/mysql/my.cnf.";
//            System.out.println("Original Message : " + secretMessage);
            byte[] stringToEncrypt = secretMessage.getBytes();
            
            CipherController cc = new CipherController();
            
//            byte[] fileToEncrypt = binaryFileReader(FILE_TO_ENCRYPT);  
            byte[] encryptedData = cc.encryptData(stringToEncrypt, list_cert);
            byte[] encryptedDER = FileHelper.CMStoDER(encryptedData);
            
            FileHelper.binaryFileWriter(FILE_TARGET, encryptedDER);
            System.out.println("Encrypted Message : " + new String(encryptedData));
            System.out.println("==========================");
            
            byte[] rawData = cc.decryptData(encryptedData, pkcc_01.getPriv_key(), 1);
            String decryptedMessage = new String(rawData);
            System.out.println("Decrypted Message for Cert 1 : " + decryptedMessage);
            System.out.println("==========================");
            
            rawData = cc.decryptData(encryptedData, pkcc_02.getPriv_key(), 2);
            decryptedMessage = new String(rawData);
            System.out.println("Decrypted Message for Cert 2 : " + decryptedMessage);
            System.out.println("==========================");
        } catch (KeyStoreException | UnrecoverableKeyException | IOException | CertificateEncodingException | CMSException ex) {
            Logger.getLogger(EnvelopedData.class.getName()).log(Level.SEVERE, null, ex);
        }
            
    }
}
