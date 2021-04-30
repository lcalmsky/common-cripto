package io.lcalmsky.common_crypto.converter;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.lcalmsky.common_crypto.util.RsaUtils;
import org.springframework.http.HttpInputMessage;
import org.springframework.http.HttpOutputMessage;
import org.springframework.http.converter.AbstractHttpMessageConverter;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.http.converter.HttpMessageNotWritableException;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;

public class RsaMessageConverter<T> extends AbstractHttpMessageConverter<T> {

    private final PrivateKey privateKey;
    private final PublicKey publicKey;
    private final ObjectMapper objectMapper;

    public RsaMessageConverter(PublicKey publicKey, PrivateKey privateKey) {
        this.publicKey = publicKey;
        this.privateKey = privateKey;
        objectMapper = new ObjectMapper();
    }

    @Override
    protected boolean supports(Class<?> clazz) {
        return true;
    }

    @Override
    protected T readInternal(Class<? extends T> clazz, HttpInputMessage inputMessage) throws IOException, HttpMessageNotReadableException {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        byte[] buffer = new byte[1024];
        InputStream inputStream = inputMessage.getBody();
        for (int length; (length = inputStream.read(buffer)) != -1; ) outputStream.write(buffer, 0, length);
        String encryptedText = outputStream.toString("UTF-8");
        return objectMapper.readValue(RsaUtils.decrypt(encryptedText, privateKey), clazz);
    }

    @Override
    protected void writeInternal(T t, HttpOutputMessage outputMessage) throws IOException, HttpMessageNotWritableException {
        String content = objectMapper.writeValueAsString(t);
        String encryptedText = RsaUtils.encrypt(content, publicKey);
        outputMessage.getBody().write(encryptedText.getBytes(StandardCharsets.UTF_8));
    }
}
