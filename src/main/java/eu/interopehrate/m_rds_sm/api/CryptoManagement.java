package eu.interopehrate.m_rds_sm.api;

import android.content.Context;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.concurrent.ExecutionException;

import javax.crypto.KeyAgreement;
import javax.crypto.spec.SecretKeySpec;


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
    public PrivateKey getPrivateKey(Context context, String keystoreAlias) throws UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, CertificateException, IOException;

    /**
     *
     * Responsible for loading RSAPublicKe from Keystore
     *
     * @param context
     *
     * @return RSAPublicKe
     *
     */
    public RSAPublicKey getPublicKey(Context context, String keystoreAlias) throws CertificateException, NoSuchAlgorithmException, IOException, KeyStoreException;

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

    /**
     *
     * Responsible for decrypted the scanned data
     *
     */
    public String decrypt(String encryptedPayload, String symKey) throws Exception;

    String decryptb(byte[] encryptedPayload, String symKey) throws Exception;

    /**
     *
     * Responsible for decrypted the scanned data
     *
     */
    public String encrypt(String payload, String symKey) throws Exception;

    byte[] encryptb(String payload, String symKey) throws Exception;

    /**
     *
     * Responsible for random AES 256bit key generation the scanned data
     *
     */
    String generateSymmtericKey() throws NoSuchAlgorithmException;

    /**
     *
     * Responsible for Diffie-Hellman Key Exchange
     * Alice creates her own DH key pair
     *
     */
    public KeyPair aliceInitKeyPair() throws Exception;

    /**
     *
     * Responsible for Diffie-Hellman Key Exchange
     * Alice creates and initializes her DH KeyAgreement object
     *
     */
    public KeyAgreement aliceKeyAgreement(KeyPair aliceKpair) throws Exception;

    /**
     *
     * Responsible for Diffie-Hellman Key Exchange
     * Alice encodes her public key, and sends it over to Bob.
     *
     */
    public byte[] alicePubKeyEnc(KeyPair aliceKpair) throws Exception;

    /**
     *
     * Responsible for Diffie-Hellman Key Exchange
     * Bob has received Alice's public key in encoded format.
     * He instantiates a DH public key from the encoded key material.
     * Bob gets the DH parameters associated with Alice's public key.
     * He must use the same parameters when he generates his own key pair.
     * Bob creates his own DH key pair
     */
    public KeyPair bobInitKeyPair(byte[] alicePubKeyEnc) throws Exception;

    /**
     *
     * Responsible for Diffie-Hellman Key Exchange
     * Bob creates and initializes his DH KeyAgreement object
     */
    public KeyAgreement bobKeyAgreement(KeyPair bobKpair) throws Exception;

    /**
     *
     * Responsible for Diffie-Hellman Key Exchange
     * Bob encodes his public key, and sends it over to Alice.
     */
    public byte[] bobPubKeyEnc(KeyPair bobKpair) throws Exception;

    /**
     *
     * Responsible for Diffie-Hellman Key Exchange
     * Alice uses Bob's public key of her version of the DH
     * Before she can do so, she has to instantiate a DH public key
     * from Bob's encoded key material.
     * Alice generate the (same) shared secret.
     */
    public KeyAgreement aliceKeyAgreementFin(byte[] bobPubKeyEnc, KeyAgreement aliceKeyAgree) throws Exception;

    /**
     *
     * Responsible for Diffie-Hellman Key Exchange
     * Bob generate the (same) shared secret.
     *
     */
    public KeyAgreement bobKeyAgreementFin(byte[] alicePubKeyEnc, KeyAgreement bobKeyAgree) throws Exception;

    /**
     *
     * Responsible for Diffie-Hellman Key Exchange
     * Create an AES SecretKey object using the shared secret
     *
     */
    SecretKeySpec generateSymmtericKey(byte[] sharedSecret, int size);

    /**
     *
     * Responsible for consent generation of the RRC to the S-EHR App
     *
     */
    public String generateConsent();


    X509Certificate toX509Certificate(byte[] certificateData) throws CertificateException;

}
