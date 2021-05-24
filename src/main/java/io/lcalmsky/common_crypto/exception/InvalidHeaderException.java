package io.lcalmsky.common_crypto.exception;

import org.springframework.http.HttpStatus;

public class InvalidHeaderException extends EncryptionException {
    protected InvalidHeaderException(String statusText) {
        super(HttpStatus.BAD_REQUEST, statusText);
    }

    public static InvalidHeaderException thrown() {
        return new InvalidHeaderException("invalid header");
    }
}
