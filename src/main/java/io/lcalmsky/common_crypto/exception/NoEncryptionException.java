package io.lcalmsky.common_crypto.exception;

import org.springframework.http.HttpStatus;

public class NoEncryptionException extends EncryptionException {

    private static final NoEncryptionException INSTANCE = new NoEncryptionException();

    protected NoEncryptionException() {
        super(HttpStatus.BAD_REQUEST, "request body should be encrypted");
    }

    public static NoEncryptionException thrown() {
        return INSTANCE;
    }
}
