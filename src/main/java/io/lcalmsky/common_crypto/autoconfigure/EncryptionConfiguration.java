package io.lcalmsky.common_crypto.autoconfigure;

import io.lcalmsky.common_crypto.converter.RsaMessageConverter;
import io.lcalmsky.common_crypto.util.RsaUtils;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.BeanFactory;
import org.springframework.beans.factory.BeanFactoryAware;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.context.EnvironmentAware;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.http.converter.json.JsonbHttpMessageConverter;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
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
import java.util.Optional;

@Configuration
@ComponentScan({"io.lcalmsky.common_crypto"})
@Slf4j
public class EncryptionConfiguration implements EnvironmentAware, BeanFactoryAware {

    private Environment environment;
    private ConfigurableListableBeanFactory beanFactory;

    @Bean(name = "amlRestTemplate")
    @ConditionalOnProperty(name = "crypto.uses-client", havingValue = "true")
    public RestTemplate amlRestTemplate() {
        String base64EncodedPublicKey = Optional.ofNullable(environment.getProperty("crypto.rsa.public-key"))
                .orElseThrow(() -> new IllegalArgumentException("\"crypto.rsa.public-key\" with Base64 encoded value should be in application properties"));
        String base64EncodedPrivateKey = Optional.ofNullable(environment.getProperty("crypto.rsa.private-key"))
                .orElseThrow(() -> new IllegalArgumentException("\"crypto.rsa.private-key\" with Base64 encoded value should be in application properties"));
        return new RestTemplateBuilder()
                .additionalMessageConverters(
                        new MappingJackson2HttpMessageConverter(),
                        new RsaMessageConverter<>(publicKey(base64EncodedPublicKey), privateKey(base64EncodedPrivateKey))
                )
                .build();
    }

    private PublicKey publicKey(String publicKey) {
        return RsaUtils.getPublicKeyFromBase64String(publicKey);
    }

    private PrivateKey privateKey(String privateKey) {
        return RsaUtils.getPrivateKeyFromBase64String(privateKey);
    }

//    @Override
//    public void setImportMetadata(AnnotationMetadata importMetadata) {
//        Map<String, Object> annotationAttributeMap = importMetadata.getAnnotationAttributes(EnableEncryption.class.getName());
//        AnnotationAttributes annotationAttributes = AnnotationAttributes.fromMap(annotationAttributeMap);
//        if (Optional.ofNullable(annotationAttributes).map(a -> a.getBoolean("usesClient")).orElse(false)) {
//            String publicKey = Optional.ofNullable(environment.getProperty("crypto.rsa.public-key"))
//                    .orElseThrow(() -> new IllegalStateException("\"crypto.rsa.public-key\" should be in application properties"));
//            String privateKey = Optional.ofNullable(environment.getProperty("crypto.rsa.private-key"))
//                    .orElseThrow(() -> new IllegalStateException("\"crypto.rsa.private-key\" should be in application properties"));
//            RestTemplate bean = amlRestTemplate(publicKey, privateKey);
//            beanFactory.registerSingleton("amlRestTemplate", bean);
//        }
//        log.info("@@@@@@ usesServer");
//        if (Optional.ofNullable(annotationAttributes).map(a -> a.getBoolean("usesServer")).orElse(false)) {
//            log.info("@@@@@@ start");
//            String publicKey = Optional.ofNullable(environment.getProperty("crypto.rsa.public-key"))
//                    .orElseThrow(() -> new IllegalStateException("\"crypto.rsa.public-key\" should be in application properties"));
//            String privateKey = Optional.ofNullable(environment.getProperty("crypto.rsa.private-key"))
//                    .orElseThrow(() -> new IllegalStateException("\"crypto.rsa.private-key\" should be in application properties"));
//            ServerEncryptionFilter serverEncryptionFilter = new ServerEncryptionFilter(publicKey(publicKey), privateKey(privateKey));
////            FilterRegistrationBean<ServerEncryptionFilter> bean = filterRegistrationBean(serverEncryptionFilter);
////            log.info("@@@@@ {}", bean.getClass().getCanonicalName());
////            beanFactory.registerSingleton(bean.getClass().getCanonicalName(), bean);
//            beanFactory.registerSingleton(serverEncryptionFilter.getClass().getCanonicalName(), serverEncryptionFilter);
//        }
//    }

    @Override
    public void setEnvironment(Environment environment) {
        this.environment = environment;
    }

    @Override
    public void setBeanFactory(BeanFactory beanFactory) throws BeansException {
        this.beanFactory = (ConfigurableListableBeanFactory) beanFactory;
    }

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
}
