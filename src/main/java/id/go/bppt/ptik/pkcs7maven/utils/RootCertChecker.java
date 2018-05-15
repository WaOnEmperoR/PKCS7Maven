/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package id.go.bppt.ptik.pkcs7maven.utils;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

/**
 *
 * @author Rachmawan
 */
public class RootCertChecker {
    public RootCertChecker()
    {
    
    }
    
    private PublicKey getPublicKeyFromFile (String filepath) throws CertificateException, FileNotFoundException
    {
        CertificateFactory fact = CertificateFactory.getInstance("X.509");
        FileInputStream is = new FileInputStream (filepath);
        X509Certificate cer = (X509Certificate) fact.generateCertificate(is);
        PublicKey key = cer.getPublicKey();
        
        return key;
    }
    
    public void checkCertificate (X509Certificate probe, String filepath) throws CertificateException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, SignatureException, FileNotFoundException
    {
        PublicKey key = getPublicKeyFromFile(filepath);
        probe.verify(key);
    }
}
