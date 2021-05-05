//package io.lcalmsky.common_crypto.autoconfigure;
//
//import com.fasterxml.jackson.core.JsonProcessingException;
//import com.fasterxml.jackson.core.type.TypeReference;
//import com.fasterxml.jackson.databind.ObjectMapper;
//import io.lcalmsky.common_crypto.converter.RsaMessageConverter;
//import io.lcalmsky.common_crypto.exception.EncryptionException;
//import io.lcalmsky.common_crypto.exception.NoEncryptionException;
//import io.lcalmsky.common_crypto.util.RsaUtils;
//import lombok.RequiredArgsConstructor;
//import lombok.SneakyThrows;
//import lombok.extern.slf4j.Slf4j;
//import org.springframework.beans.factory.annotation.Value;
//import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
//import org.springframework.boot.web.client.RestTemplateBuilder;
//import org.springframework.context.EnvironmentAware;
//import org.springframework.context.annotation.Bean;
//import org.springframework.context.annotation.ComponentScan;
//import org.springframework.context.annotation.Configuration;
//import org.springframework.context.annotation.ImportAware;
//import org.springframework.core.annotation.Order;
//import org.springframework.core.env.Environment;
//import org.springframework.core.type.AnnotationMetadata;
//import org.springframework.stereotype.Component;
//import org.springframework.util.StreamUtils;
//import org.springframework.web.client.RestTemplate;
//import org.springframework.web.filter.OncePerRequestFilter;
//
//import javax.servlet.*;
//import javax.servlet.http.HttpServletRequest;
//import javax.servlet.http.HttpServletRequestWrapper;
//import javax.servlet.http.HttpServletResponse;
//import javax.servlet.http.HttpServletResponseWrapper;
//import java.io.*;
//import java.nio.charset.StandardCharsets;
//import java.security.PrivateKey;
//import java.security.PublicKey;
//import java.util.Collections;
//import java.util.Map;
//import java.util.Optional;
//
//@Configuration
//@ComponentScan({"io.lcalmsky.common_crypto"})
//@Slf4j
//public class EncryptionConfigurationBackup implements EnvironmentAware, ImportAware {
//    static int CNT = 0;
//
//    private Environment environment;
//
//    @Bean(name = "amlRestTemplate")
//    @ConditionalOnProperty(name = "crypto.uses-client", havingValue = "true")
//    @Order(9)
//    public RestTemplate amlRestTemplate() {
//        log.info("@@@@@ {} {}", CNT++, Thread.currentThread().getStackTrace()[1]);
//        String base64EncodedPublicKey = Optional.ofNullable(environment.getProperty("crypto.rsa.public-key"))
//                .orElseThrow(() -> new IllegalArgumentException("\"crypto.rsa.public-key\" with Base64 encoded value should be in application properties"));
//        String base64EncodedPrivateKey = Optional.ofNullable(environment.getProperty("crypto.rsa.private-key"))
//                .orElseThrow(() -> new IllegalArgumentException("\"crypto.rsa.private-key\" with Base64 encoded value should be in application properties"));
//        return new RestTemplateBuilder()
//                .additionalMessageConverters(new RsaMessageConverter(publicKey(base64EncodedPublicKey), privateKey(base64EncodedPrivateKey)))
//                .build();
//    }
//
//    @Bean
//    @ConditionalOnProperty(prefix = "crypto.rsa", name = {"public-key", "private-key", "uses-client", "uses-server"}, matchIfMissing = true)
//    public PublicKey publicKey(@Value("${crypto.rsa.public-key}") String base64EncodedPublicKey) {
//        log.info("@@@@@ {} {}", CNT++, Thread.currentThread().getStackTrace()[1]);
//        return RsaUtils.getPublicKeyFromBase64String(base64EncodedPublicKey);
//    }
//
//    @Bean
//    @ConditionalOnProperty(prefix = "crypto.rsa", name = {"public-key", "private-key", "uses-client", "uses-server"}, matchIfMissing = true)
//    public PrivateKey privateKey(@Value("${crypto.rsa.private-key}") String base64EncodedPrivateKey) {
//        log.info("@@@@@ {} {}", CNT++, Thread.currentThread().getStackTrace()[1]);
//        return RsaUtils.getPrivateKeyFromBase64String(base64EncodedPrivateKey);
//    }
//
//    @Override
//    public void setEnvironment(Environment environment) {
//        log.info("@@@@@ {} {}", CNT++, Thread.currentThread().getStackTrace()[1]);
//        this.environment = environment;
//    }
//
//    @Override
//    public void setImportMetadata(AnnotationMetadata importMetadata) {
//        log.info("@@@@@ {} {}", CNT++, Thread.currentThread().getStackTrace()[1]);
//    }
//
//    @Slf4j
//    @RequiredArgsConstructor
//    @Component
//    @ConditionalOnProperty(name = "crypto.uses-server", havingValue = "true")
//    public static class ServerEncryptionFilter implements Filter {
//        private final PublicKey publicKey;
//        private final PrivateKey privateKey;
//        private final ObjectMapper objectMapper = new ObjectMapper();
//
//        @Override
//        public void init(FilterConfig filterConfig) {
//            log.info("@@@@@ {} {}", CNT++, Thread.currentThread().getStackTrace()[1]);
//            log.info("add encryption filter from @EnableRsaEncryption");
//        }
//
//        @SneakyThrows
//        @Override
//        public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) {
//            BufferedRequestWrapper bufferedRequest = new BufferedRequestWrapper((HttpServletRequest) request);
//            if (bufferedRequest.getRequestBody().length() != 0) setRequest(bufferedRequest);
//            chain.doFilter(bufferedRequest, response);
//            setResponse((HttpServletResponse) response);
//        }
//
//        private void setRequest(BufferedRequestWrapper bufferedRequest) throws JsonProcessingException {
//            Map<String, String> map = objectMapper.readValue(bufferedRequest.getRequestBody(), new TypeReference<Map<String, String>>() {
//            });
//            log.info("@@@@@ request map: {}", map);
//            log.info("@@@@@ decrypted: {}", RsaUtils.decrypt(Optional.ofNullable(map.get("encrypted"))
//                    .orElseThrow(NoEncryptionException::thrown), privateKey));
//            bufferedRequest.setRequestBody(RsaUtils.decrypt(Optional.ofNullable(map.get("encrypted"))
//                    .orElseThrow(NoEncryptionException::thrown), privateKey));
//        }
//
//        private void setResponse(HttpServletResponse response) {
//            BufferedResponseWrapper bufferedResponse = new BufferedResponseWrapper(response);
//            bufferedResponse.encryptThenWrite(publicKey);
//        }
//
//        @Override
//        public void destroy() {
//            log.info("remove encryption filter");
//        }
//
//        public static class BufferedRequestWrapper extends HttpServletRequestWrapper implements Serializable {
//            private static final long serialVersionUID = -2420421613561723478L;
//            private final byte[] bytes;
//            private String requestBody;
//
//            public BufferedRequestWrapper(HttpServletRequest request) throws IOException {
//                super(request);
//                log.info("@@@@@ {} {}", CNT++, Thread.currentThread().getStackTrace()[1]);
//                InputStream in = super.getInputStream();
//                bytes = StreamUtils.copyToByteArray(in);
//                requestBody = new String(bytes, StandardCharsets.UTF_8);
//            }
//
//            @Override
//            public ServletInputStream getInputStream() {
//                return new ServletInStream(new ByteArrayInputStream(bytes));
//            }
//
//            public String getRequestBody() {
//                return this.requestBody;
//            }
//
//            public void setRequestBody(String requestBody) {
//                this.requestBody = requestBody;
//            }
//
//            static class ServletInStream extends ServletInputStream {
//                private final InputStream is;
//
//                public ServletInStream(ByteArrayInputStream bis) {
//                    this.is = bis;
//                }
//
//                @Override
//                public boolean isFinished() {
//                    return false;
//                }
//
//                @Override
//                public boolean isReady() {
//                    return false;
//                }
//
//                @Override
//                public void setReadListener(ReadListener listener) {
//                }
//
//                @Override
//                public int read() throws IOException {
//                    return is.read();
//                }
//
//                @Override
//                public int read(byte[] bytes) throws IOException {
//                    return is.read(bytes);
//                }
//            }
//        }
//
//        public static class BufferedResponseWrapper extends HttpServletResponseWrapper {
//
//            private final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
//            private final PrintWriter writer = new PrintWriter(outputStream);
//            private final ObjectMapper objectMapper = new ObjectMapper();
//
//            public BufferedResponseWrapper(HttpServletResponse response) {
//                super(response);
//            }
//
//            @Override
//            public ServletOutputStream getOutputStream() {
//
//                return new ServletOutputStream() {
//                    @Override
//                    public boolean isReady() {
//                        return false;
//                    }
//
//                    @Override
//                    public void setWriteListener(WriteListener listener) {
//
//                    }
//
//                    @Override
//                    public void write(int b) {
//                        outputStream.write(b);
//                    }
//
//                    @Override
//                    public void write(byte[] b) throws IOException {
//                        outputStream.write(b);
//                    }
//                };
//            }
//
//            @Override
//            public PrintWriter getWriter() {
//                return writer;
//            }
//
//            @Override
//            public void flushBuffer() {
//                writer.flush();
//            }
//
//            public String getResponseData() {
//                return outputStream.toString();
//            }
//
//            @SneakyThrows
//            public void encryptThenWrite(PublicKey publicKey) {
//                log.info("@@@@@ response data: {}", getResponseData());
//                Map<String, String> encrypted = Collections.singletonMap("encrypted", getResponseData());
//                String encryptedText = objectMapper.writeValueAsString(encrypted);
//                ServletOutputStream outputStream = getOutputStream();
//                outputStream.write(RsaUtils.encrypt(encryptedText, publicKey).getBytes(StandardCharsets.UTF_8));
//                outputStream.flush();
//                outputStream.close();
//            }
//        }
//    }
//
//    @Component
//    @ConditionalOnProperty(name = "crypto.uses-server", havingValue = "true")
//    public static class ExceptionHandlerFilter extends OncePerRequestFilter {
//        private final ObjectMapper objectMapper = new ObjectMapper();
//
//        public ExceptionHandlerFilter() {
//            log.info("@@@@@ {} {}", CNT++, Thread.currentThread().getStackTrace()[1]);
//        }
//
//        @Override
//        protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws IOException, ServletException {
//            try {
//                filterChain.doFilter(request, response);
//            } catch (EncryptionException e) {
//                response.setStatus(e.getStatusCode().value());
//                response.getWriter().write(objectMapper.writeValueAsString(Collections.singletonMap("reason", e.getMessage())));
//            }
//        }
//    }
//}
