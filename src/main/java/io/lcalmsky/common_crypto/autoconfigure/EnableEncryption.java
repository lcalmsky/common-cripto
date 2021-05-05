package io.lcalmsky.common_crypto.autoconfigure;

import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

import java.lang.annotation.*;

/**
 *
 */
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Documented
@Configuration
@Import(EncryptionConfiguration.class)
public @interface EnableEncryption {

    /**
     * client encrypts request body and then decrypts response body<br>
     * uses properties(crypto.uses-client=true) instead of this.
     *
     * @return true if uses this function
     */
    @Deprecated
    boolean usesClient() default false;

    /**
     * set algorithm to be used for encryption on the client. <br>
     * Currently, only RSA is provided. <br>
     *
     * @return Algorithm to be used for encryption on the client
     */
    Algorithm clientAlgorithm() default Algorithm.RSA;

    /**
     * server decrypts request body and then encrypts response body <br>
     * uses properties(crypto.uses-server=true) instead of this.
     *
     * @return true if uses this function
     */
    @Deprecated
    boolean usesServer() default false;

    /**
     * set algorithm to be used for encryption on the server. <br>
     * Currently, only RSA is provided.
     *
     * @return Algorithm to be used for encryption on the server
     */
    Algorithm serverAlgorithm() default Algorithm.RSA;

    enum Algorithm {
        RSA
    }
}
