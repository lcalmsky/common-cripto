package io.lcalmsky.common_crypto.converter;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import io.lcalmsky.common_crypto.util.RsaUtils;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpInputMessage;
import org.springframework.http.HttpOutputMessage;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.http.converter.HttpMessageNotWritableException;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Type;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Collections;
import java.util.Map;

@Slf4j
public class AesMessageConverter extends MappingJackson2HttpMessageConverter {

    private final PrivateKey privateKey;
    private final PublicKey publicKey;
    private final ObjectMapper objectMapper;

    public AesMessageConverter(PublicKey publicKey, PrivateKey privateKey) {
        this.publicKey = publicKey;
        this.privateKey = privateKey;
        objectMapper = new ObjectMapper();
        objectMapper.configure(SerializationFeature.FAIL_ON_EMPTY_BEANS, false);
        objectMapper.enable(DeserializationFeature.ACCEPT_EMPTY_STRING_AS_NULL_OBJECT);
    }

    @Override
    protected boolean supports(Class<?> clazz) {
        return true;
    }

    @Override
    protected Object readInternal(Class<?> clazz, HttpInputMessage inputMessage) throws IOException, HttpMessageNotReadableException {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        byte[] buffer = new byte[1024];
        InputStream inputStream = inputMessage.getBody();
        for (int length; (length = inputStream.read(buffer)) != -1; ) outputStream.write(buffer, 0, length);
        String encryptedText = outputStream.toString("UTF-8");
        Map<String, String> responseMap = objectMapper.readValue(RsaUtils.decrypt(encryptedText, privateKey), new TypeReference<Map<String, String>>() {
        });
        return objectMapper.readValue(RsaUtils.decrypt(responseMap.get("encrypted"), privateKey), clazz);
    }

    @Override
    protected void writeInternal(Object object, Type type, HttpOutputMessage outputMessage) throws IOException, HttpMessageNotWritableException {
        String content = objectMapper.writeValueAsString(object);
        String encryptedText = RsaUtils.encrypt(content, publicKey);
        Map<String, String> encrypted = Collections.singletonMap("encrypted", encryptedText);
        outputMessage.getBody().write(objectMapper.writeValueAsString(encrypted).getBytes(StandardCharsets.UTF_8));
    }
}
