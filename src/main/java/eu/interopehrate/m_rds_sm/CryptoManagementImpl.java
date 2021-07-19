package eu.interopehrate.m_rds_sm;


import android.content.Context;
import android.os.Build;
import android.util.Base64;
import android.util.Log;

import androidx.annotation.RequiresApi;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;
import java.util.concurrent.ExecutionException;

import eu.interopehrate.m_rds_sm.api.CryptoManagement;
import eu.interopehrate.security_commons.services.ca.CAServiceFactory;
import eu.interopehrate.security_commons.services.ca.api.CAService;

import static java.nio.charset.StandardCharsets.UTF_8;

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

    /**
     * Keystore password
     */
    //TODO: how?
    public final static String KEYSTORE_ALIAS = "GRxavi";


    private CAService ca;

    public CryptoManagementImpl(String caUrl) {
        ca = CAServiceFactory.create(caUrl);
    }

    @Override
    //TODO: test
    // KEYSTORE_ALIAS
    public PrivateKey getPrivateKey(Context context)
            throws UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, CertificateException, IOException {
        String path = getKeystorePath(context);
        FileInputStream fis = new FileInputStream(path);
        KeyStore keystore = loadKeystore(fis);
        PrivateKey privateKey = (PrivateKey) keystore.getKey(KEYSTORE_ALIAS,KEYSTORE_PASSWORD.toCharArray());
        return privateKey;
    }

    @Override
    //TODO: test
    // KEYSTORE_ALIAS
    public RSAPublicKey getPublicKey(Context context) throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {
        String path = getKeystorePath(context);
        FileInputStream fis = new FileInputStream(path);
        KeyStore keystore = loadKeystore(fis);
        Certificate cert = keystore.getCertificate(KEYSTORE_ALIAS);
        PublicKey pkey = cert.getPublicKey();
        RSAPublicKey publicKey = (RSAPublicKey) pkey;
        return publicKey;
    }

    @Override
    //todo: delete
    public void fetchCertificate(Context context) throws NoSuchAlgorithmException, NoSuchProviderException {
        KeyPair keyPair = generateKeyPair();
        createKeyStore(keyPair,context);
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

    //TODO: delete
    public KeyStore createKeyStore(KeyPair keyPair, Context context) {
        KeyStore ks = null;

        FileOutputStream fos = null;
        try {
            fos = new FileOutputStream(getKeystorePath(context));

            // Build empty keystore
            ks = KeyStore.getInstance(KeyStore.getDefaultType());
            X509Certificate certificate = generateCertificate( keyPair );
            ks.load(null, KEYSTORE_PASSWORD.toCharArray());
            ks.setKeyEntry( KEYSTORE_ALIAS,
                    keyPair.getPrivate(),
                    null,
                    new X509Certificate[]{
                            certificate
                    } );
            ks.store(fos, KEYSTORE_PASSWORD.toCharArray()); // Export keystore in a file
        } catch (Exception e) {
            Log.e("Exception",e.getMessage());
        } finally {
            try {
                if (fos != null)
                    fos.close();
            } catch (IOException e) {
                // Intentionally blank
            }
        }
        return ks;
    }

    //TODO: To be replaced form the CA
    //TODO: delete
    private static X509Certificate generateCertificate(KeyPair keyPair)
            throws OperatorCreationException, CertificateException, InvalidKeyException,
            NoSuchAlgorithmException, NoSuchProviderException, SignatureException
    {
        String issuerString = "C=IT, O=InteropEHRate, OU=InteropEHRate Certificate, CN=Mario Rossi, UID=0f3e03e0-b4ca-4a76-821d-bdef16267ed0";
        // subjects name - the same as we are self signed.
        String subjectString = "C=IT, O=InteropEHRate, OU=InteropEHRate Certificate, CN=Mario Rossi, UID=0f3e03e0-b4ca-4a76-821d-bdef16267ed0";
        // String issuerString = "C=DE, O=datenkollektiv, OU=Planets Debug Certificate";
        // subjects name - the same as we are self signed.
        // String subjectString = "C=DE, O=datenkollekitv, OU=Planets Debug Certificate";
        X500Name issuer = new X500Name( issuerString );
        BigInteger serial = BigInteger.ONE;
        Date notBefore = new Date();
        Date notAfter = new Date( System.currentTimeMillis() + ( 365 * 24 * 60 * 60 ) );
        X500Name subject = new X500Name( subjectString );
        PublicKey publicKey = keyPair.getPublic();
        JcaX509v3CertificateBuilder v3Bldr = new JcaX509v3CertificateBuilder( issuer,
                serial,
                notBefore,
                notAfter,
                subject,
                publicKey );
        X509CertificateHolder certHldr = v3Bldr
                .build( new JcaContentSignerBuilder( "SHA1WithRSA" ).build( keyPair.getPrivate() ) );
        X509Certificate cert = new JcaX509CertificateConverter().getCertificate( certHldr );
        cert.checkValidity( new Date() );
        cert.verify( keyPair.getPublic() );
        return cert;
    }

    public KeyPair generateKeyPair() throws NoSuchAlgorithmException, NoSuchProviderException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance( "RSA" );
        SecureRandom random = SecureRandom.getInstance( "SHA1PRNG");
        keyGen.initialize( 1024, random );
        return keyGen.generateKeyPair();
    }

    @Override
    public byte[] getUserCertificate(final String userAlias) throws IOException, ExecutionException, InterruptedException {
        return ca.getUserCertificate(userAlias);
    }

    @Override
    public Boolean validateUserCertificate(byte[] certificateData) throws IOException, ExecutionException, InterruptedException {
        return ca.validateUserCertificate(certificateData);
    }

}
