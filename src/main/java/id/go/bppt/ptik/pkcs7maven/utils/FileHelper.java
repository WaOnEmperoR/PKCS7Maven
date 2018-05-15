/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package id.go.bppt.ptik.pkcs7maven.utils;

import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.imageio.ImageIO;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.cms.CMSSignedData;

/**
 *
 * @author Rachmawan
 */
public class FileHelper {
    public FileHelper() {
    }
    
    public static byte[] binaryFileReader(String path) throws FileNotFoundException, IOException {
        File file = new File(path);
        byte[] fileData = new byte[(int) file.length()];
        try (DataInputStream dis = new DataInputStream(new FileInputStream(file))) {
            dis.readFully(fileData);
            
            System.out.println("FILE READ SUCCESSFUL");
        }

        return fileData;
    }
    
    public static void binaryFileWriter (String path, byte[] content)
    {
        try (FileOutputStream fileOuputStream = new FileOutputStream(path)) {
            fileOuputStream.write(content);
            
            System.out.println("FILE HAS BEEN WRITTEN");
        } catch (FileNotFoundException ex) {
            Logger.getLogger(FileHelper.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(FileHelper.class.getName()).log(Level.SEVERE, null, ex);
        }
        
    }
    
    public static byte[] BitmapToByteArray (String path)
    {
        File fnew=new File(path);
        BufferedImage originalImage;
        try {
            originalImage = ImageIO.read(fnew);
            ByteArrayOutputStream baos=new ByteArrayOutputStream();
            ImageIO.write(originalImage, "jpg", baos );
            byte[] imageInByte=baos.toByteArray();
            
            return imageInByte;
        } catch (IOException ex) {
            Logger.getLogger(FileHelper.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        return null;
    }
    
    public static byte[] CMStoDER(CMSSignedData sigData) throws IOException
    {
        ByteArrayInputStream inStream = new ByteArrayInputStream(sigData.getEncoded());
        ASN1InputStream asnInputStream = new ASN1InputStream(inStream);
        
        ASN1Primitive asp = asnInputStream.readObject();
        byte[] result = asp.getEncoded("DER");
        
        return result;
    }
    
    public static byte[] CMStoDER(byte[] envData) throws IOException
    {
        ByteArrayInputStream inStream = new ByteArrayInputStream(envData);
        ASN1InputStream asnInputStream = new ASN1InputStream(inStream);
        
        ASN1Primitive asp = asnInputStream.readObject();
        byte[] result = asp.getEncoded("DER");
        
        return result;
    }
    
}
