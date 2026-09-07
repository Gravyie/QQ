package com.meridian.auth.legacy;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

/** Branch-terminal channel from the 2004 core banking integration. */
public final class BranchTerminalCipher {

    /** Triple DES. Disallowed by NIST SP 800-131A Rev.2 since 2023. */
    public static byte[] encryptBranchMessage(byte[] message, byte[] key) throws Exception {
        Cipher cipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "DESede"));
        return cipher.doFinal(message);
    }

    /** Single DES. Present only in the ATM reconciliation path. */
    public static byte[] encryptReconciliation(byte[] message, byte[] key) throws Exception {
        Cipher cipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "DES"));
        return cipher.doFinal(message);
    }
}
