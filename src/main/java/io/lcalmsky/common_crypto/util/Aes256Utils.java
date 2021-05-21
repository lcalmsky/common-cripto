package io.lcalmsky.common_crypto.util;

import org.apache.tomcat.util.codec.binary.StringUtils;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Optional;

public class Aes256Utils {
    private static final String ENC_FORMAT = "AES/CBC/PKCS5Padding";
    private byte[] key;
    private byte[] iv;

    public Aes256Utils(String initKey, String initIv) {
        Optional.ofNullable(initKey).filter(x -> x.length() == 16 || x.length() == 32 || x.length() == 48)
                .ifPresent(x -> {
                    key = initKey.getBytes();
                    iv = initIv.getBytes();
                });
    }

    private Cipher getCryptCipher(int mode) {
        SecretKeySpec SecureKey = new SecretKeySpec(key, "AES");
        IvParameterSpec InitialVector = new IvParameterSpec(iv);
        Cipher crypto;
        try {
            crypto = Cipher.getInstance(ENC_FORMAT);
            crypto.init(mode, SecureKey, InitialVector);
            return crypto;
        } catch (InvalidKeyException e) {
            throw new IllegalStateException("invalid Key");
        } catch (InvalidAlgorithmParameterException e) {
            throw new IllegalStateException("invalid algorithm parameter");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("no such algorithm found: " + ENC_FORMAT);
        } catch (NoSuchPaddingException e) {
            throw new IllegalStateException("no such padding found: " + ENC_FORMAT);
        }
    }

    public String encrypt(String clearStr) {
        try {
            return Base64.getEncoder().encodeToString(getCryptCipher(Cipher.ENCRYPT_MODE).doFinal(StringUtils.getBytesUtf8(clearStr)));
        } catch (IllegalBlockSizeException e) {
            throw new IllegalStateException("illegal block size");
        } catch (BadPaddingException e) {
            throw new IllegalStateException("bad padding");
        }
    }

    public String decrypt(String encStr) {
        try {
            return StringUtils.newStringUtf8(getCryptCipher(Cipher.DECRYPT_MODE).doFinal(Base64.getDecoder().decode(encStr)));
        } catch (IllegalBlockSizeException e) {
            throw new IllegalStateException("illegal block size");
        } catch (BadPaddingException e) {
            throw new IllegalStateException("bad padding");
        }
    }
}
