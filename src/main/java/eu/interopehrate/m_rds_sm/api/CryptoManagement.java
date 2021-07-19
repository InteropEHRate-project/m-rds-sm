package eu.interopehrate.m_rds_sm.api;

import android.content.Context;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.concurrent.ExecutionException;


/*
 *		Author: UBITECH
 *		Project: InteropEHRate - www.interopehrate.eu
 *
 *	Description: Interface of M-RDS-SM library.
 *	It allows the S-EHR application to securely share data.
 *
 */
public interface CryptoManagement {
    /**
     *
     * Responsible for loading PrivateKey from Keystore
     *
     * @param context
     *
     * @return PrivateKey
     *
     */
    public PrivateKey getPrivateKey(Context context) throws UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, CertificateException, IOException;

    /**
     *
     * Responsible for loading RSAPublicKe from Keystore
     *
     * @param context
     *
     * @return RSAPublicKe
     *
     */
    public RSAPublicKey getPublicKey(Context context) throws CertificateException, NoSuchAlgorithmException, IOException, KeyStoreException;

    /**
     *
     * Responsible for signing payload data
     *
     * @param payload Tha payload to signed
     */
    public String signPayload(String payload, PrivateKey privateKey)
            throws IOException,
            SignatureException,
            InvalidKeyException,
            NoSuchAlgorithmException,
            InvalidKeySpecException;

    /**
     *
     * Responsible for verifing the HCP's scanned signature
     *
     * @param publicKey
     * @param payload
     * @param signature
     *
     * @return boolean
     *
     */
    public boolean verifySignature(RSAPublicKey publicKey, byte[] payload, byte[] signature)
            throws UnsupportedEncodingException,
            NoSuchAlgorithmException,
            InvalidKeyException,
            SignatureException;

    /**
     *
     * Responsible for get the keystore path
     *
     * @param context the application context
     *
     * @return boolean
     */
    String getKeystorePath(Context context);

    byte[] getUserCertificate(String userAlias) throws IOException, ExecutionException, InterruptedException;

    Boolean validateUserCertificate(byte[] certificateData) throws IOException, ExecutionException, InterruptedException;
}
