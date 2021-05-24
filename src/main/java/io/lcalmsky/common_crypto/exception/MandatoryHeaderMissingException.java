package io.lcalmsky.common_crypto.exception;

import org.springframework.http.HttpStatus;

public class MandatoryHeaderMissingException extends EncryptionException {
    protected MandatoryHeaderMissingException(String statusText) {
        super(HttpStatus.BAD_REQUEST, statusText);
    }

    public static MandatoryHeaderMissingException thrown() {
        return new MandatoryHeaderMissingException("'Authorization' header should be provided");
    }
}
