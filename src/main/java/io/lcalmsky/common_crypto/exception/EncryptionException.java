package io.lcalmsky.common_crypto.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.client.HttpStatusCodeException;

public class EncryptionException extends HttpStatusCodeException {
    protected EncryptionException(HttpStatus statusCode, String statusText) {
        super(statusCode, statusText);
    }
}
