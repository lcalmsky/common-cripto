## Overview

애너테이션과 설정을 이용해 암호화 기능을 제공합니다.

### Server Encryption

아래 두 항목을 적용하고나면 요청 전문을 복호화하고 응답 전문을 암호화하는 필터(`ServerEncryptionFilter`)와 암호화 실패시 예외를 처리하기위한 필터(`ExceptionHandlerFilter`)가
등록됩니다.

#### application.yml

설정 파일에 다음 항목을 추가합니다.

```yaml
crypto:
  uses-server: true
  rsa:
    public-key: <base64 encoded public key>
    private-key: <base64 encoded private key>
```

#### @EnableEncryption

소스 코드 내에 애너테이션을 추가합니다.

```java

@SpringBootApplication
@EnableEncryption
public class FooApplication {

}
```

### Client Encryption

아래 두 항목을 적용하면 요청 전문을 암호화하고 응답 전문을 복호화하는 `interceptor`가 추가된 `RestTemplate` bean 을 등록합니다.

#### application.yml

설정 파일에 다음 항목을 추가합니다.

```yaml
crypto:
  uses-client: true
  rsa:
    public-key: <base64 encoded public key>
    private-key: <base64 encoded private key>
```

#### @EnableEncryption

소스 코드 내에 애너테이션을 추가합니다.

```java

@SpringBootApplication
@EnableEncryption
public class FooApplication {

}
```

연동할 곳에 RestTemplate을 주입 후 전문을 암호화하여 사용할 곳에 해당 restTemplate 객체를 사용하여 연동합니다.

##### @Autowired 사용 예제

```java

@Service
public class FooService {
    @Autowired
    private RestTemplate encryptedRestTemplate;
}
```

##### 생성자 사용 예제

```java

@Service
@RequiredArgsConstructor
public class FooService {
    private final RestTemplate encryptedRestTemplate;
}
```

```java

@Service
public class FooService {
    private final RestTemplate encryptedRestTemplate;

    public FooService(RestTemplate encryptedRestTemplate) {
        this.encryptedRestTemplate = encryptedRestTemplate;
    }
}
```

##### 연동 예제

```java

@Service
@RequiredArgsConstructor
public class FooService {
    private final RestTemplate encryptedRestTemplate;

    public void insertStudent(Student student) {
        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.setContentType(MediaType.APPLICATION_JSON);
        httpHeaders.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));
        encryptedRestTemplate.getMessageConverters().forEach(c -> log.info("{}", c));
        HttpEntity<String> httpEntity = new HttpEntity<>("{\n" +
                "  \"name\": \"홍길동\",\n" +
                "  \"age\": 20,\n" +
                "  \"phoneNumber\": \"01012345678\"\n" +
                "}",
                httpHeaders);
        encryptedRestTemplate.exchange("http://localhost:8080/student", HttpMethod.POST, httpEntity, Void.class);
    }
}
```

### Precautions

- annotation attribute를 이용한 암호화 활성화 기능은 현재 지원하지 않습니다.

### Future Works

* annotation attribute를 통해 암호화 알고리즘 추가
