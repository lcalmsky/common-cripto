package io.lcalmsky.common_crypto;

import io.lcalmsky.common_crypto.exception.InvalidHeaderException;

import java.util.Base64;

public class BasicAuthFilterTest {
    public static void main(String[] args) {
        String authorization = "Basic c3RyOkFtbDEyIyQ=";
        String value = authorization.substring("Basic".length() + 1);
        System.out.println(value);
        String decoded = new String(Base64.getDecoder().decode(value));
        System.out.println(decoded);
        if (!decoded.contains(":")) throw InvalidHeaderException.thrown();
        String[] split = decoded.split(":");
        String user = split[0];
        System.out.println(user);
    }
}
