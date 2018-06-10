/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package id.go.bppt.ptik.tsa;

import id.go.bppt.ptik.pkcs7maven.utils.FileHelper;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.util.Collection;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.apache.commons.io.FileUtils;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.InputStreamEntity;
import org.apache.http.impl.client.HttpClientBuilder;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.tsp.TSPAlgorithms;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.tsp.TimeStampToken;

/**
 *
 * @author Rachmawan
 */
public class TSAUtils {

    private static byte[] getTimeStampToken(String url, byte[] digest, int TSA) throws NoSuchAlgorithmException {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        if (url.equals("")) {
            url = "http://202.46.12.56:8080/signserver/process?workerName=TimeStampSigner";
        }

        HttpClient client = HttpClientBuilder.create().build();
        HttpPost post = new HttpPost(url);

        TimeStampRequestGenerator reqGen = new TimeStampRequestGenerator();
        //request TSA to return certificate
        reqGen.setCertReq(false);

//        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
//        messageDigest.update("messageImprint".getBytes());
//        byte[] digest = messageDigest.digest();
        //make a TSP request this is a dummy sha1 hash (20 zero bytes) and nonce=100
        TimeStampRequest request
                = reqGen.generate(TSPAlgorithms.SHA256,
                        digest, BigInteger.valueOf(100));

        ByteArrayInputStream bais = null;
        try {
            bais = new ByteArrayInputStream(request.getEncoded());

            post.setHeader("Content-type", "application/timestamp-query");
            post.setEntity(new InputStreamEntity(bais));

            HttpResponse response = client.execute(post);

            InputStream in = response.getEntity().getContent();
            //InputStream in = post.gegetResponseBodyAsStream();
            System.out.println(response.getEntity().getContentType().getName());
            System.out.println(response.getEntity().getContentType().getValue());
            System.out.println("Response Code : "
                    + response.getStatusLine().getStatusCode());

            //read TSP response
            TimeStampResponse resp = new TimeStampResponse(in);

            resp.validate(request);

            TimeStampToken tsToken = resp.getTimeStampToken();

            byte[] hasil = tsToken.getEncoded();
            byte[] derku = FileHelper.CMStoDER(hasil);
            FileUtils.writeByteArrayToFile(new File("D:\\Tugas PTIK\\Pemilu Elektronik\\cobaTSA.DER"), derku);
//            SignerId signer_id = tsToken.getSID();
//
//            BigInteger cert_serial_number = signer_id.getSerialNumber();
//
//            System.out.println(signer_id.getSerialNumber());

            return tsToken.getEncoded();
        } catch (IOException e) {
        } catch (TSPException ex) {
            Logger.getLogger(TSAUtils.class.getName()).log(Level.SEVERE, null, ex);
        }

        return null;
    }

    public static CMSSignedData addTimestamp(String tsaUrl, CMSSignedData signedData, int id) {
        Collection<SignerInformation> signerInfos = signedData.getSignerInfos().getSigners();

        // get signature of first signer (should be the only one)
        SignerInformation si = signerInfos.iterator().next();
        byte[] signature = si.getSignature();
        
//        byte[] signDigest = MessageDigest.getInstance(TSPAlgorithms.SHA1, new BouncyCastleProvider()).digest(si.getSignature());
        
        try {
//            byte[] signDigest = MessageDigest.getInstance("SHA-256", "BC").update(si.getSignature());
            MessageDigest messageDigest = MessageDigest.getInstance("SHA256");
            messageDigest.update(si.getSignature());
            byte[] digest = messageDigest.digest();

            // send request to TSA
            byte[] token = getTimeStampToken(tsaUrl, digest, id);

            // create new SignerInformation with TS attribute
            Attribute tokenAttr = new Attribute(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken,
                    new DERSet(ASN1Primitive.fromByteArray(token)));
            ASN1EncodableVector timestampVector = new ASN1EncodableVector();
            timestampVector.add(tokenAttr);
            AttributeTable at = new AttributeTable(timestampVector);
            si = SignerInformation.replaceUnsignedAttributes(si, at);
            signerInfos.clear();
            signerInfos.add(si);
            SignerInformationStore newSignerStore = new SignerInformationStore(signerInfos);

            // create new signed data
            CMSSignedData newSignedData = CMSSignedData.replaceSigners(signedData, newSignerStore);
            return newSignedData;
        } catch (NoSuchAlgorithmException | IOException ex) {
            Logger.getLogger(TSAUtils.class.getName()).log(Level.SEVERE, null, ex);
        }

        return null;
    }
}
