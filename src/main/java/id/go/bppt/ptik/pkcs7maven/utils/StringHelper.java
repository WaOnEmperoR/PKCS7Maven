/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package id.go.bppt.ptik.pkcs7maven.utils;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 *
 * @author Rachmawan
 */
public class StringHelper {
    
    public static Date ASN1DateParser(String rawdate) throws StringFormatException, ParseException
    {
        Date ret_date = null;
       
        boolean status = false;
        String regex = "(\\[\\d{12}Z\\])";
        Pattern ptr = Pattern.compile(regex);
        Matcher m = ptr.matcher(rawdate);
        while (m.find())
        {
            status=true;
        }
        
        if (status==false)
        {
            throw new StringFormatException("Wrong ASN.1 Date format");
        }
        
        String year = rawdate.substring(1, 3);
        String month = rawdate.substring(3, 5);
        String date = rawdate.substring(5, 7);
        String hour = rawdate.substring(7, 9);
        String minute = rawdate.substring(9, 11); 
        String second = rawdate.substring(11, 13); 
        
        String concatenated = year + " " + month + " " + date + " " + hour + ":" + minute + ":" + second + " UTC";

        SimpleDateFormat parser = new SimpleDateFormat("y M d HH:mm:ss zzz");
        ret_date = parser.parse(concatenated);    
        
        return ret_date;
    }
    
    public static HashMap<String, String> DNFieldsMapper(String DNString)
    {
        HashMap<String,String> hm=new HashMap<>();  
          
        String[] splitByCommas = DNString.split(",");
        for (String splitByComma : splitByCommas) {
            String[] splitByEquals = splitByComma.split("=");
            hm.put(splitByEquals[0], splitByEquals[1]);
        }
        
        return hm;
    }
    

    public StringHelper() {
    }
}
