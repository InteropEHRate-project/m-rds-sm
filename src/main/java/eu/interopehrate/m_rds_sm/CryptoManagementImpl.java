package eu.interopehrate.m_rds_sm;


import android.content.Context;
import android.os.Build;
import android.util.Base64;
import android.util.Log;

import androidx.annotation.RequiresApi;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.concurrent.ExecutionException;

import javax.crypto.KeyAgreement;
import javax.crypto.spec.SecretKeySpec;

import eu.interopehrate.m_rds_sm.api.CryptoManagement;
import eu.interopehrate.m_rds_sm.util.FileUtil;
import eu.interopehrate.security_commons.consent.ConsentManagementFactory;
import eu.interopehrate.security_commons.consent.api.ConsentManagement;
import eu.interopehrate.security_commons.encryptedCommunication.EncryptedCommunicationFactory;
import eu.interopehrate.security_commons.encryptedCommunication.api.EncryptedCommunication;
import eu.interopehrate.security_commons.services.ca.CAServiceFactory;
import eu.interopehrate.security_commons.services.ca.api.CAService;

import static java.nio.charset.StandardCharsets.UTF_8;

import com.fasterxml.jackson.core.JsonProcessingException;

/*
 *		Author: UBITECH
 *		Project: InteropEHRate - www.interopehrate.eu
 *
 *	Description: Interface of M-RDS-SM library.
 *	It allows the S-EHR application to securely share data.
 *
 */

public class CryptoManagementImpl implements CryptoManagement {

    /**
     * Keystore name
     */
    public final static String KEYSTORE_NAME = "keystore.p12";

    /**
     * Keystore password
     */
    public final static String KEYSTORE_PASSWORD = "interop";

    private CAService ca;
    private EncryptedCommunication encryptedCommunication;
    private ConsentManagement consentManagement;

    public CryptoManagementImpl(String caUrl) {
        ca = CAServiceFactory.create(caUrl);
        encryptedCommunication = EncryptedCommunicationFactory.create();
        consentManagement = ConsentManagementFactory.create();
    }

    @Override
    public String getKeystoreAlias(Context context) throws IOException {
        String alias = FileUtil.LoadData(context, context.getFilesDir().getAbsolutePath() + "/alias");
        return  alias;
    }

    @Override
    public PrivateKey getPrivateKey(Context context)
            throws UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, CertificateException, IOException {
        String keystoreAlias = getKeystoreAlias(context);
        String path = getKeystorePath(context);
        FileInputStream fis = new FileInputStream(path);
        KeyStore keystore = loadKeystore(fis);
        PrivateKey privateKey = (PrivateKey) keystore.getKey(keystoreAlias,KEYSTORE_PASSWORD.toCharArray());
        return privateKey;
    }

    @Override
    public byte[] getCertificateFromKeystore(Context context)
            throws UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, CertificateException, IOException {
        String keystoreAlias = getKeystoreAlias(context);
        String path = getKeystorePath(context);
        FileInputStream fis = new FileInputStream(path);
        KeyStore keystore = loadKeystore(fis);
        Certificate cert = keystore.getCertificate(keystoreAlias);
        byte[] isoBytes = Base64.encodeToString(cert.getEncoded(), Base64.DEFAULT).getBytes("ISO-8859-1");
        return isoBytes;
    }

    @Override
    public RSAPublicKey getPublicKey(Context context) throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {
        String keystoreAlias = getKeystoreAlias(context);
        String path = getKeystorePath(context);
        FileInputStream fis = new FileInputStream(path);
        KeyStore keystore = loadKeystore(fis);
        Certificate cert = keystore.getCertificate(keystoreAlias);
        PublicKey pkey = cert.getPublicKey();
        RSAPublicKey publicKey = (RSAPublicKey) pkey;
        return publicKey;
    }

    @RequiresApi(api = Build.VERSION_CODES.KITKAT)
    @Override
    public String signPayload(String payload, PrivateKey privateKey)
            throws SignatureException, InvalidKeyException {
        Signature privateSignature = null;
        try {
            privateSignature = Signature.getInstance("SHA256withRSA");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        privateSignature.initSign(privateKey);
        privateSignature.update(payload.getBytes(UTF_8));

        byte[] signature = privateSignature.sign();

        Log.d("MSSG signature", Base64.encodeToString(signature, Base64.DEFAULT).
                replaceAll("\r", "").
                replaceAll("\n", ""));

        return Base64.encodeToString(signature, Base64.DEFAULT).
                replaceAll("\r", "").
                replaceAll("\n", "");
    }

    @Override
    public boolean verifySignature(RSAPublicKey publicKey, byte[] payload, byte[] signature)
            throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        byte[] signedPayloadContent = Base64.decode(signature, Base64.DEFAULT);

        Signature sign = Signature.getInstance("SHA256withRSA");
        sign.initVerify(publicKey);
        sign.update(payload);

        boolean result = sign.verify(signedPayloadContent);

        Log.d("MSSG verifySignature->", String.valueOf(result));

        return result;
    }

    @Override
    public String getKeystorePath(Context context) {
        return context.getFilesDir().getAbsolutePath() + "/"
                + KEYSTORE_NAME;
    }

    public KeyStore loadKeystore(FileInputStream keystoreBytes)
            throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException {
        KeyStore ks;
        ks = KeyStore.getInstance("PKCS12");

        if( keystoreBytes != null ) {
            ks.load( keystoreBytes, KEYSTORE_PASSWORD.toCharArray() );
        } else {
            System.out.println("DON NOT EXIST -> FETCH");
            ks.load( null , KEYSTORE_PASSWORD.toCharArray());
        }
        return ks;
    }

    @Override
    public byte[] getUserCertificate(final String userAlias) throws IOException, ExecutionException, InterruptedException {
        return ca.getUserCertificate(userAlias);
    }

    @Override
    public Boolean validateUserCertificate(byte[] certificateData) throws IOException, ExecutionException, InterruptedException {
        return ca.validateUserCertificate(certificateData);
    }

    @Override
    public String decrypt(String encryptedPayload, String symKey) throws Exception {
        return encryptedCommunication.decrypt(encryptedPayload, symKey);
    }

    @Override
    public String decryptb(byte[] encryptedPayload, String symKey) throws Exception {
        return encryptedCommunication.decryptb(encryptedPayload, symKey);
    }

    @Override
    public String encrypt(String payload, String symKey) throws Exception {
        return encryptedCommunication.encrypt(payload, symKey);
    }

    @Override
    public byte[] encryptb(String payload, String symKey) throws Exception {
        return encryptedCommunication.encryptb(payload, symKey);
    }

    @Override
    public String generateSymmtericKey() throws NoSuchAlgorithmException {
        return encryptedCommunication.generateSymmtericKey();
    }

    @Override
    public KeyPair aliceInitKeyPair() throws Exception {
        return encryptedCommunication.aliceInitKeyPair();
    }

    @Override
    public KeyAgreement aliceKeyAgreement(KeyPair aliceKpair) throws Exception {
        return encryptedCommunication.aliceKeyAgreement(aliceKpair);
    }

    @Override
    public byte[] alicePubKeyEnc(KeyPair aliceKpair) throws Exception {
        return encryptedCommunication.alicePubKeyEnc(aliceKpair);
    }

    @Override
    public KeyPair bobInitKeyPair(byte[] alicePubKeyEnc) throws Exception {
        return encryptedCommunication.bobInitKeyPair(alicePubKeyEnc);
    }

    @Override
    public KeyAgreement bobKeyAgreement(KeyPair bobKpair) throws Exception {
        return encryptedCommunication.bobKeyAgreement(bobKpair);
    }

    @Override
    public byte[] bobPubKeyEnc(KeyPair bobKpair) throws Exception {
        return encryptedCommunication.bobPubKeyEnc(bobKpair);
    }

    @Override
    public KeyAgreement aliceKeyAgreementFin(byte[] bobPubKeyEnc, KeyAgreement aliceKeyAgree) throws Exception {
        return encryptedCommunication.aliceKeyAgreementFin(bobPubKeyEnc, aliceKeyAgree);
    }

    @Override
    public KeyAgreement bobKeyAgreementFin(byte[] alicePubKeyEnc, KeyAgreement bobKeyAgree) throws Exception {
        return encryptedCommunication.bobKeyAgreementFin(alicePubKeyEnc, bobKeyAgree);
    }

    @Override
    public SecretKeySpec generateSymmtericKey(byte[] sharedSecret, int size) {
        return encryptedCommunication.generateSymmtericKey(sharedSecret, size);
    }

    @Override
    public String generateConsent() {
        return consentManagement.generateConsent();
    }

    @Override
    public X509Certificate toX509Certificate(byte[] certificateData) throws CertificateException {
        return ca.toX509Certificate(certificateData);
    }

    @Override
    public Boolean verifyDetachedJws(String jwsToken, String payload) throws CertificateException, JsonProcessingException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        RSAPublicKey rsaPublicKey = (RSAPublicKey)ca.getPublicKeyFromJws(jwsToken);
        String signed = ca.getSignatureFromJws(jwsToken);
        return verifySignature(rsaPublicKey,payload.getBytes(), signed.getBytes());
    }

    @Override
    public String createDetachedJws(byte[] certificateData, String signed) throws JsonProcessingException {
        return ca.createDetachedJws(certificateData, signed);
    }

}
