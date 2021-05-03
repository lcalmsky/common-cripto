package io.lcalmsky.common_crypto.util;

import io.lcalmsky.common_crypto.exception.InvalidEncryptionException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

public class RsaUtils {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    public static KeyPair generateKeyPair(String algorithm) {
        KeyPairGenerator gen;
        try {
            gen = KeyPairGenerator.getInstance(algorithm);
        } catch (NoSuchAlgorithmException e) {
            throw InvalidEncryptionException.thrown("no such algorithm: " + algorithm);
        }
        gen.initialize(1024, SECURE_RANDOM);
        return gen.genKeyPair();
    }

    public static String encrypt(String plainText, PublicKey publicKey) {
        Cipher cipher = getCipher();
        initCipher(cipher, Cipher.ENCRYPT_MODE, publicKey);
        return Base64.getEncoder().encodeToString(doFinal(cipher, plainText.getBytes(StandardCharsets.UTF_8)));
    }

    public static String decrypt(String encrypted, PrivateKey privateKey) {
        Cipher cipher = getCipher();
        initCipher(cipher, Cipher.DECRYPT_MODE, privateKey);
        return new String(doFinal(cipher, Base64.getDecoder().decode(encrypted.getBytes())), StandardCharsets.UTF_8);
    }

    public static PrivateKey getPrivateKeyFromBase64String(final String key) {
        final String privateKeyString = key.replaceAll("\\n", "").replaceAll("-{5}[ a-zA-Z]*-{5}", "");
        KeyFactory keyFactory = getKeyFactory();
        PKCS8EncodedKeySpec keySpecPKCS8 = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateKeyString));
        try {
            return keyFactory.generatePrivate(keySpecPKCS8);
        } catch (InvalidKeySpecException e) {
            throw InvalidEncryptionException.thrown("invalid key: " + key);
        }
    }

    public static PublicKey getPublicKeyFromBase64String(final String key) {
        final String publicKeyString = key.replaceAll("\\n", "").replaceAll("-{5}[ a-zA-Z]*-{5}", "");
        KeyFactory keyFactory = getKeyFactory();
        X509EncodedKeySpec keySpecX509 = new X509EncodedKeySpec(Base64.getDecoder().decode(publicKeyString));
        try {
            return keyFactory.generatePublic(keySpecX509);
        } catch (InvalidKeySpecException e) {
            throw InvalidEncryptionException.thrown("invalid key: " + key);
        }
    }

    private static KeyFactory getKeyFactory() {
        try {
            return KeyFactory.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            throw InvalidEncryptionException.thrown("no such algorithm: RSA");
        }
    }

    private static Cipher getCipher() {
        Cipher cipher;
        try {
            cipher = Cipher.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            throw InvalidEncryptionException.thrown("no such algorithm found: " + "RSA");
        } catch (NoSuchPaddingException e) {
            throw InvalidEncryptionException.thrown("no such padding found: " + "RSA");
        }
        return cipher;
    }

    private static void initCipher(Cipher cipher, int cipherMode, Key key, IvParameterSpec... ivParamSpec) {
        try {
            if (ivParamSpec != null && ivParamSpec.length > 0) cipher.init(cipherMode, key, ivParamSpec[0]);
            else cipher.init(cipherMode, key);
        } catch (InvalidKeyException e) {
            throw InvalidEncryptionException.thrown("invalid key: " + key);
        } catch (InvalidAlgorithmParameterException e) {
            throw InvalidEncryptionException.thrown("invalid algorithm parameter: " + Arrays.toString(ivParamSpec));
        }
    }

    private static byte[] doFinal(Cipher cipher, byte[] bytes) {
        byte[] encrypted;
        try {
            encrypted = cipher.doFinal(bytes);
        } catch (IllegalBlockSizeException e) {
            throw InvalidEncryptionException.thrown("illegal block size");
        } catch (BadPaddingException e) {
            throw InvalidEncryptionException.thrown("bad padding");
        }
        return encrypted;
    }
}
