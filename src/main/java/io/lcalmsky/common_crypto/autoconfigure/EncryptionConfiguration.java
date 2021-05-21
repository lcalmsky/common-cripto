package io.lcalmsky.common_crypto.autoconfigure;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import io.lcalmsky.common_crypto.converter.AesMessageConverter;
import io.lcalmsky.common_crypto.exception.EncryptionException;
import io.lcalmsky.common_crypto.exception.NoEncryptionException;
import io.lcalmsky.common_crypto.util.Aes256Utils;
import io.lcalmsky.common_crypto.util.RsaUtils;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.context.EnvironmentAware;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpRequest;
import org.springframework.http.MediaType;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.http.client.support.BasicAuthenticationInterceptor;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.authentication.AuthenticationFilter;
import org.springframework.stereotype.Component;
import org.springframework.util.StreamUtils;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServletResponseWrapper;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.*;

@Configuration
@ComponentScan({"io.lcalmsky.common_crypto"})
@Slf4j
public class EncryptionConfiguration implements EnvironmentAware, WebMvcConfigurer {

    private Environment environment;

    @Override
    public void setEnvironment(Environment environment) {
        this.environment = environment;
    }

    @Bean(name = "encryptedRestTemplate")
    @ConditionalOnProperty(name = "crypto.uses-client", havingValue = "false")
    public RestTemplate mockRestTemplate() {
        return new RestTemplate();
    }

    @Bean(name = "encryptedRestTemplate")
    @ConditionalOnProperty(name = "crypto.uses-client", havingValue = "true", matchIfMissing = true)
    public RestTemplate encryptedRestTemplate() {
        String key = Optional.ofNullable(environment.getProperty("crypto.aes.key"))
                .orElseThrow(() -> new IllegalArgumentException("\"crypto.aes.key\" with Base64 encoded value should be in application properties"));
        String iv = Optional.ofNullable(environment.getProperty("crypto.aes.iv"))
                .orElseThrow(() -> new IllegalArgumentException("\"crypto.aes.iv\" with Base64 encoded value should be in application properties"));
        return new RestTemplateBuilder()
                .additionalMessageConverters(new AesMessageConverter(key, iv))
                .additionalInterceptors(getInterceptors())
                .build();
    }

    private Collection<ClientHttpRequestInterceptor> getInterceptors() {
        Collection<ClientHttpRequestInterceptor> interceptors = new ArrayList<>();
        addBasicAuthInterceptor(interceptors);
        interceptors.add(new CustomHeaderInterceptor());
        return interceptors;
    }

    private void addBasicAuthInterceptor(Collection<ClientHttpRequestInterceptor> interceptors) {
        boolean usesBasicAuth = Optional.ofNullable(environment.getProperty("crypto.client.basic-auth.enabled", Boolean.class))
                .orElse(false);
        if (usesBasicAuth) {
            String username = Optional.ofNullable(environment.getProperty("crypto.client.basic-auth.username"))
                    .orElseThrow(() -> new IllegalArgumentException("\"crypto.client.basic-auth.username\" should be in application properties"));
            String password = Optional.ofNullable(environment.getProperty("crypto.client.basic-auth.password"))
                    .orElseThrow(() -> new IllegalArgumentException("\"crypto.client.basic-auth.password\" should be in application properties"));
            interceptors.add(new BasicAuthenticationInterceptor(username, password));
        }
    }

    @Bean
    @ConditionalOnProperty(name = "crypto.rsa.enabled", havingValue = "true")
    public PublicKey publicKey(@Value("${crypto.rsa.public-key}") String base64EncodedPublicKey) {
        return RsaUtils.getPublicKeyFromBase64String(base64EncodedPublicKey);
    }

    @Bean
    @ConditionalOnProperty(name = "crypto.rsa.enabled", havingValue = "true")
    public PrivateKey privateKey(@Value("${crypto.rsa.private-key}") String base64EncodedPrivateKey) {
        return RsaUtils.getPrivateKeyFromBase64String(base64EncodedPrivateKey);
    }

    public static class CustomHeaderInterceptor implements ClientHttpRequestInterceptor {
        @Override
        public ClientHttpResponse intercept(HttpRequest request, byte[] body, ClientHttpRequestExecution execution) throws IOException {
            request.getHeaders().set(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE);
            request.getHeaders().set(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE);
            return execution.execute(request, body);
        }
    }

    @Slf4j
    @Component
    @ConditionalOnProperty(name = "crypto.uses-server", havingValue = "true")
    public static class ServerEncryptionFilter implements Filter {
        private final ObjectMapper objectMapper;
        private final Aes256Utils aes256Utils;

        public ServerEncryptionFilter(@Value("${crypto.aes.key}") String key, @Value("${crypto.aes.iv}") String iv) {
            aes256Utils = new Aes256Utils(key, iv);
            objectMapper = new ObjectMapper();
            objectMapper.configure(SerializationFeature.FAIL_ON_EMPTY_BEANS, false);
            objectMapper.enable(DeserializationFeature.ACCEPT_EMPTY_STRING_AS_NULL_OBJECT);
        }

        @Override
        public void init(FilterConfig filterConfig) {
            log.info("add encryption filter from @EnableRsaEncryption");
        }

        @SneakyThrows
        @Override
        public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) {
            BufferedRequestWrapper bufferedRequest = new BufferedRequestWrapper((HttpServletRequest) request);
            if (bufferedRequest.getRequestBody().length() != 0) setRequest(bufferedRequest);
            chain.doFilter(bufferedRequest, response);
            setResponse((HttpServletResponse) response);
        }

        private void setRequest(BufferedRequestWrapper bufferedRequest) throws JsonProcessingException {
            Map<String, String> map = objectMapper.readValue(bufferedRequest.getRequestBody(), new TypeReference<Map<String, String>>() {
            });
            bufferedRequest.setRequestBody(aes256Utils.decrypt(Optional.ofNullable(map.get("encrypted"))
                    .orElseThrow(NoEncryptionException::thrown)));
        }

        private void setResponse(HttpServletResponse response) {
            BufferedResponseWrapper bufferedResponse = new BufferedResponseWrapper(response);
            bufferedResponse.encryptThenWrite(aes256Utils);
        }

        @Override
        public void destroy() {
            log.info("remove encryption filter");
        }

        public static class BufferedRequestWrapper extends HttpServletRequestWrapper implements Serializable {
            private static final long serialVersionUID = -2420421613561723478L;
            private byte[] bytes;
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
                this.bytes = requestBody.getBytes(StandardCharsets.UTF_8);
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
            private final ObjectMapper objectMapper = new ObjectMapper();

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
            public void encryptThenWrite(Aes256Utils aes256Utils) {
                Map<String, String> encrypted = Collections.singletonMap("encrypted", getResponseData());
                String encryptedText = objectMapper.writeValueAsString(encrypted);
                ServletOutputStream outputStream = getOutputStream();
                outputStream.write(aes256Utils.encrypt(encryptedText).getBytes(StandardCharsets.UTF_8));
                outputStream.flush();
                outputStream.close();
            }
        }
    }

    @Component
    @ConditionalOnProperty(name = "crypto.uses-server", havingValue = "true")
    public static class ExceptionHandlerFilter extends OncePerRequestFilter {
        private final ObjectMapper objectMapper = new ObjectMapper();

        @Override
        protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws IOException, ServletException {
            try {
                filterChain.doFilter(request, response);
            } catch (EncryptionException e) {
                response.setStatus(e.getStatusCode().value());
                response.getWriter().write(objectMapper.writeValueAsString(Collections.singletonMap("reason", e.getMessage())));
            }
        }
    }

    @Component
    @ConditionalOnProperty(name = "crypto.server.basic-auth.enabled", havingValue = "true")
    @EnableWebSecurity
    @RequiredArgsConstructor
    public static class WebSecurityConfig extends WebSecurityConfigurerAdapter {
        private final UserProperties userProperties;

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http
                    .csrf().disable()
                    .authorizeRequests().anyRequest().authenticated()
                    .and().httpBasic()
                    .and().addFilterBefore(new AuthenticationContextFilter());
        }

        @Override
        protected void configure(AuthenticationManagerBuilder auth) throws Exception {
            auth.userDetailsService(inMemoryUserDetailsManager());
        }

        @Bean
        public PasswordEncoder passwordEncoder() {
            return new PasswordEncoder() {
                @Override
                public String encode(CharSequence rawPassword) {
                    return Base64.getEncoder().encodeToString(rawPassword.toString().getBytes(StandardCharsets.UTF_8));
                }

                @Override
                public boolean matches(CharSequence rawPassword, String encodedPassword) {
                    return encode(rawPassword).equals(encodedPassword);
                }
            };
        }

        @Bean
        public InMemoryUserDetailsManager inMemoryUserDetailsManager() {
            Properties props = new Properties();
            userProperties.getUsers().forEach((key, value) -> props.setProperty(key, String.format("%s,%s,%s", value, "ROLE_USER", "enabled")));
            return new InMemoryUserDetailsManager(props);
        }

        @Configuration
        @EnableConfigurationProperties
        @ConfigurationProperties(prefix = "crypto.server.basic-auth")
        @Data
        public static class UserProperties {
            private Map<String, String> users = new HashMap<>();
        }
    }
}
