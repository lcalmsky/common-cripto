package io.lcalmsky.common_crypto.autoconfigure;

import io.lcalmsky.common_crypto.converter.RsaMessageConverter;
import io.lcalmsky.common_crypto.util.Aes256Utils;
import io.lcalmsky.common_crypto.util.RsaUtils;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.context.annotation.*;
import org.springframework.core.annotation.AnnotationAttributes;
import org.springframework.core.type.AnnotatedTypeMetadata;
import org.springframework.stereotype.Component;
import org.springframework.util.StreamUtils;
import org.springframework.web.client.RestTemplate;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServletResponseWrapper;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;

@Configuration
@ComponentScan({"io.lcalmsky.common_crypto"})
public class EncryptionConfiguration {

    private static <T> T extractDataFromMetadata(AnnotatedTypeMetadata metadata, Function<AnnotationAttributes, T> annotationAttributesBooleanFunction, T defaultValue) {
        Map<String, Object> annotationAttributeMap = metadata.getAnnotationAttributes(EnableEncryption.class.getName());
        AnnotationAttributes annotationAttributes = AnnotationAttributes.fromMap(annotationAttributeMap);
        return Optional.ofNullable(annotationAttributes)
                .map(annotationAttributesBooleanFunction)
                .orElse(defaultValue);
    }

    @Bean
    @Conditional(ClientCondition.class)
    public RestTemplate amlRestTemplate(@Value("${crypto.rsa.public-key}") String publicKey,
                                        @Value("${crypto.rsa.private-key}") String privateKey) {
        return new RestTemplateBuilder()
                .additionalMessageConverters(new RsaMessageConverter<>(
                        publicKey(publicKey),
                        privateKey(privateKey)))
                .build();
    }

    @Bean
    @Conditional(FieldCondition.class)
    public Aes256Utils aes256Utils(@Value("${crypto.aes256.key}") String key) {
        return new Aes256Utils(key);
    }

    @Bean
    public PublicKey publicKey(@Value("${crypto.rsa.public-key}") String publicKey) {
        return RsaUtils.getPublicKeyFromBase64String(publicKey);
    }

    @Bean
    public PrivateKey privateKey(@Value("${crypto.rsa.private-key}") String privateKey) {
        return RsaUtils.getPrivateKeyFromBase64String(privateKey);
    }

    @Component
    @Conditional(ServerCondition.class)
    @Slf4j
    @RequiredArgsConstructor
    public static class ServerEncryptionFilter implements Filter {
        private final PublicKey publicKey;
        private final PrivateKey privateKey;

        @Override
        public void init(FilterConfig filterConfig) {
            log.info("add server encryption filter from @EnableRsaEncryption");
        }

        @SneakyThrows
        @Override
        public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) {
            BufferedRequestWrapper bufferedRequest = (BufferedRequestWrapper) request;
            bufferedRequest.setRequestBody(RsaUtils.decrypt(bufferedRequest.getRequestBody(), privateKey));
            chain.doFilter(bufferedRequest, response);
            BufferedResponseWrapper bufferedResponse = new BufferedResponseWrapper((HttpServletResponse) response);
            bufferedResponse.encryptThenWrite(publicKey);
        }

        @Override
        public void destroy() {
            log.info("remove server encryption filter");
        }

        public static class BufferedRequestWrapper extends HttpServletRequestWrapper implements Serializable {
            private static final long serialVersionUID = -2420421613561723478L;
            private final byte[] bytes;
            private String requestBody;

            public BufferedRequestWrapper(HttpServletRequest request) throws IOException {
                super(request);
                InputStream in = super.getInputStream();
                bytes = StreamUtils.copyToByteArray(in);
                requestBody = new String(bytes, StandardCharsets.UTF_8);
            }

            @Override
            public ServletInputStream getInputStream() {
                return new ServletInStream(new ByteArrayInputStream(bytes));
            }

            public String getRequestBody() {
                return this.requestBody;
            }

            public void setRequestBody(String requestBody) {
                this.requestBody = requestBody;
            }

            static class ServletInStream extends ServletInputStream {
                private final InputStream is;

                public ServletInStream(ByteArrayInputStream bis) {
                    this.is = bis;
                }

                @Override
                public boolean isFinished() {
                    return false;
                }

                @Override
                public boolean isReady() {
                    return false;
                }

                @Override
                public void setReadListener(ReadListener listener) {
                }

                @Override
                public int read() throws IOException {
                    return is.read();
                }

                @Override
                public int read(byte[] bytes) throws IOException {
                    return is.read(bytes);
                }
            }
        }

        public static class BufferedResponseWrapper extends HttpServletResponseWrapper {

            private final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            private final PrintWriter writer = new PrintWriter(outputStream);

            public BufferedResponseWrapper(HttpServletResponse response) {
                super(response);
            }

            @Override
            public ServletOutputStream getOutputStream() {

                return new ServletOutputStream() {
                    @Override
                    public boolean isReady() {
                        return false;
                    }

                    @Override
                    public void setWriteListener(WriteListener listener) {

                    }

                    @Override
                    public void write(int b) {
                        outputStream.write(b);
                    }

                    @Override
                    public void write(byte[] b) throws IOException {
                        outputStream.write(b);
                    }
                };
            }

            @Override
            public PrintWriter getWriter() {
                return writer;
            }

            @Override
            public void flushBuffer() {
                writer.flush();
            }

            public String getResponseData() {
                return outputStream.toString();
            }

            @SneakyThrows
            public void encryptThenWrite(PublicKey publicKey) {
                ServletOutputStream outputStream = getOutputStream();
                outputStream.write(RsaUtils.encrypt(getResponseData(), publicKey).getBytes(StandardCharsets.UTF_8));
                outputStream.flush();
                outputStream.close();
            }
        }
    }

    static class ClientCondition implements Condition {

        @Override
        public boolean matches(ConditionContext context, AnnotatedTypeMetadata metadata) {
            return extractDataFromMetadata(metadata, a -> a.getBoolean("usesClient"), false);
        }
    }

    static class ServerCondition implements Condition {

        @Override
        public boolean matches(ConditionContext context, AnnotatedTypeMetadata metadata) {
            return extractDataFromMetadata(metadata, a -> a.getBoolean("usesServer"), false);
        }
    }

    static class FieldCondition implements Condition {
        @Override
        public boolean matches(ConditionContext context, AnnotatedTypeMetadata metadata) {
            return extractDataFromMetadata(metadata, a -> a.getBoolean("usesFieldEncryptionConverter"), false);
        }
    }
}
