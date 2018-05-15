/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package id.go.bppt.ptik.pkcs7maven.controller;

import java.io.IOException;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSEnvelopedDataGenerator;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.KeyTransRecipientInformation;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.operator.OutputEncryptor;

/**
 *
 * @author Rachmawan
 */
public class CipherController {

    public CipherController() {

    }

    public byte[] encryptData(byte[] data,
            List<X509Certificate> encryptionCertificate)
            throws CertificateEncodingException, CMSException, IOException {

        byte[] encryptedData = null;
        if (null != data && null != encryptionCertificate) {
            CMSEnvelopedDataGenerator cmsEnvelopedDataGenerator
                    = new CMSEnvelopedDataGenerator();

            JceKeyTransRecipientInfoGenerator transKeyGen_01
                    = new JceKeyTransRecipientInfoGenerator(encryptionCertificate.get(0));
            JceKeyTransRecipientInfoGenerator transKeyGen_02
                    = new JceKeyTransRecipientInfoGenerator(encryptionCertificate.get(1));
            cmsEnvelopedDataGenerator.addRecipientInfoGenerator(transKeyGen_01);
            cmsEnvelopedDataGenerator.addRecipientInfoGenerator(transKeyGen_02);

            CMSTypedData msg = new CMSProcessableByteArray(data);
            OutputEncryptor encryptor
                    = new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES256_CBC)
                            .setProvider("BC").build();

            CMSEnvelopedData cmsEnvelopedData = cmsEnvelopedDataGenerator
                    .generate(msg, encryptor);
            encryptedData = cmsEnvelopedData.getEncoded();
        }
        return encryptedData;
    }

    public byte[] decryptData(
            byte[] encryptedData,
            PrivateKey decryptionKey, int idx_cert) {

        byte[] decryptedData = null;
        if (null != encryptedData && null != decryptionKey) {
            CMSEnvelopedData envelopedData;
            try {
                envelopedData = new CMSEnvelopedData(encryptedData);

                Collection<RecipientInformation> recipients
                        = envelopedData.getRecipientInfos().getRecipients();

//                System.out.println("Size : " + recipients.size());
                KeyTransRecipientInformation recipientInfo = null;
                int step = 0;

                Iterator itr = recipients.iterator();

                while (step < idx_cert) {
                    recipientInfo
                            = (KeyTransRecipientInformation) itr.next();
                    step++;
                }

                JceKeyTransRecipient recipient
                        = new JceKeyTransEnvelopedRecipient(decryptionKey);

                decryptedData = recipientInfo.getContent(recipient);
            } catch (CMSException ex) {
                Logger.getLogger(CipherController.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
        return decryptedData;
    }
}
