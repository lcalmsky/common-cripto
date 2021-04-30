package io.lcalmsky.common_crypto.util;

import org.springframework.beans.factory.annotation.Value;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class Aes256Utils {

    private static final String ALGORITHM = "AES/CBC/PKCS5Padding";
    private final String key;
    private final String iv;

    public Aes256Utils(@Value("${crypto.aes256.key:d582e6e6753d4bdfba872c5ab8458cb6}") String key) {
        this.key = key;
        this.iv = key.substring(0, 16);
    }

    public String encrypt(String plainText) {
        Cipher cipher = getCipher();
        SecretKeySpec keySpec = new SecretKeySpec(iv.getBytes(), "AES");
        IvParameterSpec ivParamSpec = new IvParameterSpec(iv.getBytes());
        initCipher(cipher, keySpec, ivParamSpec, Cipher.ENCRYPT_MODE);
        byte[] encrypted = doFinal(cipher, plainText.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encrypted);
    }

    public String decrypt(String cipherText) {
        Cipher cipher = getCipher();
        SecretKeySpec keySpec = new SecretKeySpec(iv.getBytes(), "AES");
        IvParameterSpec ivParamSpec = new IvParameterSpec(iv.getBytes());
        initCipher(cipher, keySpec, ivParamSpec, Cipher.DECRYPT_MODE);
        byte[] decodedBytes = Base64.getDecoder().decode(cipherText);
        byte[] decrypted = doFinal(cipher, decodedBytes);
        return new String(decrypted, StandardCharsets.UTF_8);
    }

    private void initCipher(Cipher cipher, SecretKeySpec keySpec, IvParameterSpec ivParamSpec, int cipherMode) {
        try {
            cipher.init(cipherMode, keySpec, ivParamSpec);
        } catch (InvalidKeyException e) {
            throw new IllegalArgumentException("invalid key: " + key);
        } catch (InvalidAlgorithmParameterException e) {
            throw new IllegalArgumentException("invalid algorithm parameter: " + key);
        }
    }

    private Cipher getCipher() {
        Cipher cipher;
        try {
            cipher = Cipher.getInstance(ALGORITHM);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("no such algorithm found: " + ALGORITHM);
        } catch (NoSuchPaddingException e) {
            throw new IllegalStateException("no such padding found: " + ALGORITHM);
        }
        return cipher;
    }

    private byte[] doFinal(Cipher cipher, byte[] bytes) {
        byte[] encrypted;
        try {
            encrypted = cipher.doFinal(bytes);
        } catch (IllegalBlockSizeException e) {
            throw new IllegalStateException("illegal block size");
        } catch (BadPaddingException e) {
            throw new IllegalStateException("bad padding");
        }
        return encrypted;
    }
}
