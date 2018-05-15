/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package id.go.bppt.ptik.pkcs7maven.utils;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertStore;
import java.security.cert.CertificateException;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.Set;

/**
 *
 * @author Rachmawan
 */
public class ChainVerifier {

    //Credit to :
    //http://www.nakov.com/blog/2009/12/01/x509-certificate-validation-in-java-build-and-verify-chain-and-verify-clr-with-bouncy-castle/
    public ChainVerifier() {

    }

    /**
     * Attempts to build a certification chain for given certificate and to
     * verify it. Relies on a set of root CA certificates and intermediate
     * certificates that will be used for building the certification chain. The
     * verification process assumes that all self-signed certificates in the set
     * are trusted root CA certificates and all other certificates in the set
     * are intermediate certificates.
     *
     * @param cert - certificate for validation
     * @param additionalCerts - set of trusted root CA certificates that will be
     * used as "trust anchors" and intermediate CA certificates that will be
     * used as part of the certification chain. All self-signed certificates are
     * considered to be trusted root CA certificates. All the rest are
     * considered to be intermediate CA certificates.
     * @return the certification chain (if verification is successful)
     * @throws CertificateVerificationException - if the certification is not
     * successful (e.g. certification path cannot be built or some certificate
     * in the chain is expired or CRL checks are failed)
     */
    public static PKIXCertPathBuilderResult verifyCertificate(X509Certificate cert,
            Set<X509Certificate> additionalCerts)
            throws CertificateVerificationException {
        try {
            // Check for self-signed certificate
            if (isSelfSigned(cert)) {
                throw new CertificateVerificationException(
                        "The certificate is self-signed.");
            }

            // Prepare a set of trusted root CA certificates
            // and a set of intermediate certificates
            Set<X509Certificate> trustedRootCerts = new HashSet<>();
            Set<X509Certificate> intermediateCerts = new HashSet<>();
            for (X509Certificate additionalCert : additionalCerts) {
                if (isSelfSigned(additionalCert)) {
                    trustedRootCerts.add(additionalCert);
                } else {
                    intermediateCerts.add(additionalCert);
                }
            }

            // Attempt to build the certification chain and verify it
            PKIXCertPathBuilderResult verifiedCertChain
                    = verifyCertificate(cert, trustedRootCerts, intermediateCerts);

            // The chain is built and verified. Return it as a result
            return verifiedCertChain;
        } catch (CertPathBuilderException certPathEx) {
            throw new CertificateVerificationException(
                    "Error building certification path: "
                    + cert.getSubjectX500Principal(), certPathEx);
        } catch (CertificateVerificationException cvex) {
            throw cvex;
        } catch (InvalidAlgorithmParameterException | InvalidKeyException | NoSuchAlgorithmException | NoSuchProviderException | SignatureException | CertificateException ex) {
            throw new CertificateVerificationException(
                    "Error verifying the certificate: "
                    + cert.getSubjectX500Principal(), ex);
        }
    }

    /**
     * Checks whether given X.509 certificate is self-signed.
     *
     * @param cert
     * @return
     * @throws java.security.cert.CertificateException
     * @throws java.security.NoSuchAlgorithmException
     * @throws java.security.NoSuchProviderException
     * @throws java.security.InvalidKeyException
     * @throws java.security.SignatureException
     */
    public static boolean isSelfSigned(X509Certificate cert)
            throws CertificateException, NoSuchAlgorithmException,
            NoSuchProviderException, InvalidKeyException, SignatureException {
        try {
            // Try to verify certificate signature with its own public key
            PublicKey key = cert.getPublicKey();
            cert.verify(key);
            return true;
        } catch (SignatureException | InvalidKeyException sigEx) {
            // Invalid signature --> not self-signed
            return false;
        }
        // Invalid key --> not self-signed
    }

    /**
     * Attempts to build a certification chain for given certificate and to
     * verify it. Relies on a set of root CA certificates (trust anchors) and a
     * set of intermediate certificates (to be used as part of the chain).
     *
     * @param cert - certificate for validation
     * @param trustedRootCerts - set of trusted root CA certificates
     * @param intermediateCerts - set of intermediate certificates
     * @return the certification chain (if verification is successful)
     * @throws java.security.InvalidAlgorithmParameterException
     * @throws java.security.NoSuchAlgorithmException
     * @throws java.security.NoSuchProviderException
     * @throws java.security.cert.CertPathBuilderException
     */
    public static PKIXCertPathBuilderResult verifyCertificate(X509Certificate cert, Set<X509Certificate> trustedRootCerts,
            Set<X509Certificate> intermediateCerts) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, CertPathBuilderException {
        // Create the selector that specifies the starting certificate
        X509CertSelector selector = new X509CertSelector();
        selector.setCertificate(cert);

        System.out.format("%-32s%s\n", "Number of intermediate CA", intermediateCerts.size());
        System.out.format("%-32s%s\n", "Number of trusted CA", trustedRootCerts.size());

        // Create the trust anchors (set of root CA certificates)
        Set<TrustAnchor> trustAnchors = new HashSet<>();
        for (X509Certificate trustedRootCert : trustedRootCerts) {
            trustAnchors.add(new TrustAnchor(trustedRootCert, null));
        }

        // Configure the PKIX certificate builder algorithm parameters
        PKIXBuilderParameters pkixParams
                = new PKIXBuilderParameters(trustAnchors, selector);

        // Disable CRL checks (this is done manually as additional step)
        pkixParams.setRevocationEnabled(false);

        // Specify a list of intermediate certificates
        CertStore intermediateCertStore = CertStore.getInstance("Collection",
                new CollectionCertStoreParameters(intermediateCerts));
        pkixParams.addCertStore(intermediateCertStore);

        // Build and verify the certification chain
        CertPathBuilder builder = CertPathBuilder.getInstance("PKIX");
        PKIXCertPathBuilderResult result
                = (PKIXCertPathBuilderResult) builder.build(pkixParams);
        return result;
    }

}
