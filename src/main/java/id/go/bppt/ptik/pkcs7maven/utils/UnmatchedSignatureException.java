/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package id.go.bppt.ptik.pkcs7maven.utils;

/**
 *
 * @author Rachmawan
 */
public class UnmatchedSignatureException extends Exception{
    public UnmatchedSignatureException()
    {
    
    }
    
    public UnmatchedSignatureException(String message)
    {
        super(message);
    }
}
