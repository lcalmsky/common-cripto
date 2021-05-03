package io.lcalmsky.common_crypto.exception;

import org.springframework.http.HttpStatus;

public class InvalidEncryptionException extends EncryptionException {

    protected InvalidEncryptionException(String message) {
        super(HttpStatus.FORBIDDEN, message);
    }

    public static InvalidEncryptionException thrown(String message) {
        return new InvalidEncryptionException(message);
    }
}
