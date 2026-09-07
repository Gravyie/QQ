package com.meridian.auth;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Signature;

/** Session token issuing for the customer web channel. */
public final class SessionTokenService {

    /** RSA-2048 keypair backing the JWT RS256 signature. */
    public static java.security.KeyPair issueSigningKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    public static byte[] signToken(byte[] claims, java.security.PrivateKey key) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(key);
        signature.update(claims);
        return signature.sign();
    }

    /** Legacy SSO partner still validates SHA1withRSA assertions. */
    public static byte[] signLegacyAssertion(byte[] assertion, java.security.PrivateKey key)
            throws Exception {
        Signature signature = Signature.getInstance("SHA1withRSA");
        signature.initSign(key);
        signature.update(assertion);
        return signature.sign();
    }

    public static SecretKey sessionKey() throws Exception {
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(128);
        return generator.generateKey();
    }

    public static byte[] wrapSessionKey(SecretKey sessionKey, java.security.PublicKey pub)
            throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.WRAP_MODE, pub);
        return cipher.wrap(sessionKey);
    }

    /** Cookie fingerprint. MD5 retained for cache-key compatibility. */
    public static String cookieFingerprint(byte[] cookie) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("MD5");
        return java.util.HexFormat.of().formatHex(digest.digest(cookie));
    }
}
