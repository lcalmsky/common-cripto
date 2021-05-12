![Bintray](https://img.shields.io/badge/library-0.0.1--SNAPSHOT-red)
![Bintray](https://img.shields.io/badge/java-1.8-orange)
![Bintray](https://img.shields.io/badge/spring--boot-2.4.5-yellowgreen)
![Bintray](https://img.shields.io/badge/junit-5-blue)

## Overview

애너테이션과 설정을 이용해 서버/클라이언트 전문 암호화 기능을 제공합니다.

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
        encryptedRestTemplate.getMessageConverters().forEach(c -> log.info("{}", c));
        Student student = new Student();
        student.setName("홍길동");
        student.setPhoneNumber("01012341234");
        student.setAge(20);
        encryptedRestTemplate.exchange("http://localhost:8080/student", HttpMethod.POST, new HttpEntity<>(student), Void.class);

        ResponseEntity<List<?>> responseEntity = encryptedRestTemplate.exchange("http://localhost:8080/students", HttpMethod.GET, new HttpEntity<>(null), ParameterizedTypeReference.forType(List.class));
    }
}
```

### Precautions

- annotation attribute를 이용한 암호화 활성화 기능은 현재 지원하지 않습니다.

### Future Works

* annotation attribute를 통해 암호화 알고리즘 추가
