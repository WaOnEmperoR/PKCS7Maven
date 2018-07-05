/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package id.go.bppt.ptik.pkcs7maven.controller;

import id.go.bppt.ptik.pkcs7maven.utils.CertificateVerificationException;
import id.go.bppt.ptik.pkcs7maven.utils.ChainVerifier;
import id.go.bppt.ptik.pkcs7maven.utils.FileHelper;
import id.go.bppt.ptik.pkcs7maven.utils.PrivateKey_CertChain;
import id.go.bppt.ptik.pkcs7maven.utils.RootCertChecker;
import id.go.bppt.ptik.pkcs7maven.utils.StringFormatException;
import id.go.bppt.ptik.pkcs7maven.utils.StringHelper;
import id.go.bppt.ptik.pkcs7maven.utils.UnmatchedSignatureException;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertStore;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.apache.commons.io.FileUtils;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaCertStoreBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.encoders.Hex;

/**
 *
 * @author Rachmawan
 */
public class SignatureController {

    /**
     * @return the rootCertCandidate
     */
    public static X509Certificate getRootCertCandidate() {
        return rootCertCandidate;
    }

    /**
     * @param aRootCertCandidate the rootCertCandidate to set
     */
    public static void setRootCertCandidate(X509Certificate aRootCertCandidate) {
        rootCertCandidate = aRootCertCandidate;
    }

    /**
     * @return the root_cert_path
     */
    public String getRoot_cert_path() {
        return root_cert_path;
    }

    /**
     * @param root_cert_path the root_cert_path to set
     */
    public void setRoot_cert_path(String root_cert_path) {
        this.root_cert_path = root_cert_path;
    }

    /**
     * @return the DN_fields
     */
    public HashMap<String, String> getDN_fields() {
        return DN_fields;
    }

    /**
     * @param DN_fields the DN_fields to set
     */
    public void setDN_fields(HashMap<String, String> DN_fields) {
        this.DN_fields = DN_fields;
    }

    private static X509Certificate rootCertCandidate;
    private String root_cert_path;
    private HashMap<String, String> DN_fields; 

    public CMSSignedData CMSGenerator(byte[] content, PrivateKey_CertChain pkcc, boolean encapsulate) {
        Security.addProvider(new BouncyCastleProvider());

        try {
            //Sign
            Signature signature = Signature.getInstance("SHA256WithRSA", "BC");
            signature.initSign(pkcc.getPriv_key());
            signature.update(content);
            byte[] signed = signature.sign();
            System.out.format("%-32s%s\n", "Signature of digest of content", Hex.toHexString(signed));

            //Digest of Signature
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(signed);
            System.out.format("%-32s%s\n", "Digest of Signature", Hex.toHexString(hash));

            //Build CMS
            X509Certificate cert = pkcc.getSingle_cert();
            List certList = new ArrayList();
            CMSTypedData msg = new CMSProcessableByteArray(content);

            System.out.format("%-32s%s\n", "Length of Certificate Chain", pkcc.getChain().length);

            certList.addAll(Arrays.asList(pkcc.getChain()));

            Store certs = new JcaCertStore(certList);
            CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
            ContentSigner sha1Signer = new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC").build(pkcc.getPriv_key());
            gen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().setProvider("BC").build()).build(sha1Signer, cert));
            gen.addCertificates(certs);
            CMSSignedData sigData = gen.generate(msg, encapsulate);

            return sigData;

        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeyException | SignatureException | CertificateEncodingException | OperatorCreationException | CMSException ex) {
            Logger.getLogger(SignatureController.class.getName()).log(Level.SEVERE, null, ex);
        }

        return null;
    }

    public int VerifyCMS(byte[] originalBytes, byte[] signatureBytes) throws UnmatchedSignatureException, StringFormatException, ParseException, IOException {
        Security.addProvider(new BouncyCastleProvider());

        int verified = 0;

        CMSSignedData cms;
        try {
            cms = new CMSSignedData(new CMSProcessableByteArray(originalBytes), signatureBytes);

            Store store = cms.getCertificates();
            
            CertStore certStore = new JcaCertStoreBuilder().setProvider("BC").addCertificates(cms.getCertificates()).build();
            SignerInformationStore signers = cms.getSignerInfos();
            Collection c = signers.getSigners();
            
            System.out.format("%-32s%s\n", "is it Detached?", cms.isDetachedSignature());
            
            // Verify signature
            System.out.format("%-32s%s\n", "Number of Signer(s)", c.size());
            
            Iterator it = c.iterator();
            while (it.hasNext()) {
                SignerInformation signer = (SignerInformation) it.next();
                Collection certCollection = store.getMatches(signer.getSID());

                AttributeTable attributes = signer.getSignedAttributes();
                Attribute attribute = attributes.get(CMSAttributes.messageDigest);
                DEROctetString digest = (DEROctetString) attribute.getAttrValues().getObjectAt(0);

                // if these values are different, the exception is thrown
                String octet_digest = Hex.toHexString(digest.getOctets());
                System.out.format("%-32s%s\n", "Digest Octets", octet_digest);

                JcaX509CertificateConverter converter = new JcaX509CertificateConverter().setProvider("BC");

                ArrayList<X509CertificateHolder> listCertDatFirm = new ArrayList(store.getMatches(null));
                System.out.format("%-32s%d\n", "Number of cert Holders All", listCertDatFirm.size());

                try {
                    verifyChain(listCertDatFirm);
                } catch (CertificateVerificationException ex) {
                    System.out.println("CERTIFICATE CHAIN VERIFICATION FAILED");
                    Logger.getLogger(SignatureController.class.getName()).log(Level.SEVERE, null, ex);
                    throw new UnmatchedSignatureException("Certificate Chain verification failed");
                }
                System.out.println("CERTIFICATE CHAIN VERIFIED");

                Collection<X509CertificateHolder> holders = store.getMatches(signer.getSID());

                Iterator certIt = certCollection.iterator();
                X509CertificateHolder certHolder = (X509CertificateHolder) certIt.next();
                X509Certificate certFromSignedData = new JcaX509CertificateConverter().setProvider(new BouncyCastleProvider()).getCertificate(certHolder);

                Principal princ = certFromSignedData.getIssuerDN();

                //Get Signer Name
                Principal p = certFromSignedData.getSubjectDN();
                System.out.format("%-32s%s\n", "Signer Distinguished Name", p.getName());
                
//                1.2.840.113549.1.9.16.6.2.14
                //Get Signing Time
//                org.bouncycastle.asn1.cms.Attribute signingTime = attributes.get(new ASN1ObjectIdentifier("1.2.840.113549.1.9.5"));
//                org.bouncycastle.asn1.cms.Attribute signingTime = attributes.get(new ASN1ObjectIdentifier("1.2.840.113549.1.9.16.6.2.14"));
                org.bouncycastle.asn1.cms.Attribute signingTime = attributes.get(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken);
//                PKCSObjectIdentifiers.id_aa_signatureTimeStampToken
                String asn1time = signingTime.getAttrValues().toString();
                System.out.format("%-32s%s\n", "Signing Time (RAW format)", asn1time);

                Date signtime = StringHelper.ASN1DateParser(asn1time);
                SimpleDateFormat formatter = new SimpleDateFormat("dd MMM yyyy hh:mm:ss zzz");
                String formattedDate = formatter.format(signtime);
                System.out.format("%-32s%s\n", "Signing Time (Pretty format)", formattedDate);
                
                try{
                    RootCertChecker rc = new RootCertChecker();

                    rc.checkCertificate(getRootCertCandidate(), getRoot_cert_path());
                }
                catch(FileNotFoundException | InvalidKeyException | NoSuchAlgorithmException | NoSuchProviderException | SignatureException | CertificateException ex)
                {
                    System.out.println("ROOT CERT VERIFICATION FAILED");
                    throw new UnmatchedSignatureException("The System does not recognized this root Certificate");
                }
                System.out.println("ROOT CERTIFICATE VERIFIED");
                            
                if (signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider(new BouncyCastleProvider()).build(certFromSignedData))) {
                    System.out.println("SIGNATURE VALUE VERIFIED <BY BOUNCY CASTLE STANDARD>");
                    // Return the content digest (hash of content)
                    System.out.format("%-32s%s\n", "Content Digest", Arrays.toString(signer.getContentDigest()));
                    verified++;
                } else {
                    System.out.println("SIGNATURE VALUE VERIFICATION <BY BOUNCY CASTLE STANDARD> FAILED");
                }                
                
                }
            } catch (CMSException | GeneralSecurityException | OperatorCreationException ex) {
                Logger.getLogger(SignatureController.class.getName()).log(Level.SEVERE, null, ex);
            } finally {
            }
        
        if (verified<1)
        {
            throw new UnmatchedSignatureException("Verification Failed");
        }

        return verified;
    }
    
    public byte[] verifyCMSNotDetached(byte[] cmsBytes) throws UnmatchedSignatureException, IOException
    {
        Security.addProvider(new BouncyCastleProvider());

        int verified = 0;
        byte[] returnBytes = null;
        
        CMSSignedData cms;
        try {
            cms = new CMSSignedData(cmsBytes);

            Store store = cms.getCertificates();
            
            CertStore certStore = new JcaCertStoreBuilder().setProvider("BC").addCertificates(cms.getCertificates()).build();
            SignerInformationStore signers = cms.getSignerInfos();
            Collection c = signers.getSigners();
            
            returnBytes = (byte[]) cms.getSignedContent().getContent();
            
            // Is it Detached Signature or not
            System.out.format("%-32s%s\n", "Is it Detached?", cms.isDetachedSignature());
            
            // Get number of signers
            System.out.format("%-32s%s\n", "Number of Signer(s)", c.size());
            
            Iterator it = c.iterator();
            while (it.hasNext()) {
                SignerInformation signer = (SignerInformation) it.next();
                Collection certCollection = store.getMatches(signer.getSID());

                JcaX509CertificateConverter converter = new JcaX509CertificateConverter().setProvider("BC");

                ArrayList<X509CertificateHolder> listCertDatFirm = new ArrayList(store.getMatches(null));
                System.out.format("%-32s%d\n", "Number of cert Holders All", listCertDatFirm.size());

                try {
                    verifyChain(listCertDatFirm);
                } catch (CertificateVerificationException ex) {
                    System.out.println("CERTIFICATE CHAIN VERIFICATION FAILED");
                    Logger.getLogger(SignatureController.class.getName()).log(Level.SEVERE, null, ex);
                    throw new UnmatchedSignatureException("Certificate Chain verification failed");
                }
                System.out.println("CERTIFICATE CHAIN VERIFIED");

                Collection<X509CertificateHolder> holders = store.getMatches(signer.getSID());

                Iterator certIt = certCollection.iterator();
                X509CertificateHolder certHolder = (X509CertificateHolder) certIt.next();
                X509Certificate certFromSignedData = new JcaX509CertificateConverter().setProvider(new BouncyCastleProvider()).getCertificate(certHolder);

                Principal princ = certFromSignedData.getIssuerDN();

                //Get Signer Name
                Principal p = certFromSignedData.getSubjectDN();
                System.out.format("%-32s%s\n", "Signer Distinguished Name", p.getName());
                
                this.setDN_fields(StringHelper.DNFieldsMapper(p.getName()));
                
                try{
                    RootCertChecker rc = new RootCertChecker();

                    rc.checkCertificate(getRootCertCandidate(), getRoot_cert_path());
                }
                catch(FileNotFoundException | InvalidKeyException | NoSuchAlgorithmException | NoSuchProviderException | SignatureException | CertificateException ex)
                {
                    System.out.println("ROOT CERT VERIFICATION FAILED");
                    throw new UnmatchedSignatureException("The System does not recognized this root Certificate");
                }
                System.out.println("ROOT CERTIFICATE VERIFIED");
                            
                if (signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider(new BouncyCastleProvider()).build(certFromSignedData))) {
                    System.out.println("SIGNATURE VALUE VERIFIED <BY BOUNCY CASTLE STANDARD>");
                    // Return the content digest (hash of content)
                    System.out.format("%-32s%s\n", "Content Digest", Hex.toHexString(signer.getContentDigest()));
                    verified++;
                } else {
                    System.out.println("SIGNATURE VALUE VERIFICATION <BY BOUNCY CASTLE STANDARD> FAILED");
                }                
                
                }
            } catch (CMSException | GeneralSecurityException | OperatorCreationException ex) {
                Logger.getLogger(SignatureController.class.getName()).log(Level.SEVERE, null, ex);
            } finally {
                
            }
        
        if (verified<1)
        {
            throw new UnmatchedSignatureException("Verification Failed");
        }

        return returnBytes;
    }

    private static PKIXCertPathBuilderResult verifyChain(ArrayList<X509CertificateHolder> cert_chain) throws CertificateException, CertificateVerificationException, IOException {
        JcaX509CertificateConverter converter = new JcaX509CertificateConverter().setProvider("BC");

        X509Certificate target_cert = null;
        Set<X509Certificate> additional_cert = new HashSet<>();
        for (int i = 0; i < cert_chain.size(); i++) {
            X509Certificate cert_loop = converter.getCertificate(cert_chain.get(i));

            if (i == 0) {
                target_cert = cert_loop;
                
                String result = FileHelper.x509CertificateToPem(target_cert);
//                FileHelper.binaryFileWriter("mycert.cer", result.getBytes());
                
                FileUtils.writeStringToFile(new File("myCert.pem"), result, "utf-8");
                
                FileHelper.binaryFileWriter("CertKu.cer", target_cert.getEncoded());
            } else {
                additional_cert.add(cert_loop);
                try {
                    if (ChainVerifier.isSelfSigned(cert_loop)) {
                        setRootCertCandidate(cert_loop);
                    }
                } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeyException | SignatureException ex) {
                    Logger.getLogger(SignatureController.class.getName()).log(Level.SEVERE, null, ex);
                }
            }

        }

        PKIXCertPathBuilderResult my_res = ChainVerifier.verifyCertificate(target_cert, additional_cert);

        return my_res;
    }
}
