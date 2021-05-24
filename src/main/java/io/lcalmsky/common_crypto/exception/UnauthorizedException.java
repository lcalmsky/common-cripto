package io.lcalmsky.common_crypto.exception;

import org.springframework.http.HttpStatus;

public class UnauthorizedException extends EncryptionException{
    protected UnauthorizedException(String statusText) {
        super(HttpStatus.UNAUTHORIZED, statusText);
    }

    public static UnauthorizedException thrown() {
        return new UnauthorizedException("unauthorized client");
    }
}
