/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package id.go.bppt.ptik.pkcs7maven.utils;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

/**
 *
 * @author Rachmawan
 */
public class PrivateKey_CertChain {
    private PrivateKey priv_key;
    private Certificate[] chain;
    private X509Certificate single_cert;

    /**
     * @return the priv_key
     */
    public PrivateKey getPriv_key() {
        return priv_key;
    }

    /**
     * @param priv_key the priv_key to set
     */
    public void setPriv_key(PrivateKey priv_key) {
        this.priv_key = priv_key;
    }

    /**
     * @return the chain
     */
    public Certificate[] getChain() {
        return chain;
    }

    /**
     * @param chain the chain to set
     */
    public void setChain(Certificate[] chain) {
        this.chain = chain;
    }
    
    /**
     * @return the single_cert
     */
    public X509Certificate getSingle_cert() {
        return single_cert;
    }

    /**
     * @param single_cert the single_cert to set
     */
    public void setSingle_cert(X509Certificate single_cert) {
        this.single_cert = single_cert;
    }
        
    public PrivateKey_CertChain(PrivateKey pk, Certificate[] theChain, X509Certificate single)
    {
        this.priv_key = pk;
        this.chain = theChain;
        this.single_cert = single;
    }
    
    public PrivateKey_CertChain(String fileP12, String passphrase, String instance) throws KeyStoreException, UnrecoverableKeyException
    {
        this.priv_key = null;
        this.chain = null;
        
        try {
            Security.addProvider(new BouncyCastleProvider());
            
            KeyStore ks = KeyStore.getInstance(instance);
            ks.load(new FileInputStream(fileP12), passphrase.toCharArray());
            
            String alias = (String) ks.aliases().nextElement();
            System.out.println("Alias : " + alias);
            PrivateKey pk = (PrivateKey) ks.getKey(alias, passphrase.toCharArray());
            Certificate[] chain = ks.getCertificateChain(alias);
            X509Certificate cert = (X509Certificate) ks.getCertificate(alias);
                        
            this.setChain(chain);
            this.setPriv_key(pk);
            this.setSingle_cert(cert);
        } catch (IOException | NoSuchAlgorithmException | CertificateException ex) {
            Logger.getLogger(PrivateKey_CertChain.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    public String loadPrivateKey() throws NoSuchAlgorithmException, InvalidKeySpecException
    {
        KeyFactory fact = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec spec = fact.getKeySpec(this.getPriv_key(),
                PKCS8EncodedKeySpec.class);
        byte[] packed = spec.getEncoded();
        String key64 = Hex.toHexString(packed); 

        Arrays.fill(packed, (byte) 0);
        return key64;
    }
    
}
