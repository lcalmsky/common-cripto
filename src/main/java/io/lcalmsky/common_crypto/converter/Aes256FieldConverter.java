//package io.lcalmsky.common_crypto.converter;
//
//import io.lcalmsky.common_crypto.util.Aes256Utils;
//import lombok.RequiredArgsConstructor;
//import org.springframework.stereotype.Component;
//
//import javax.persistence.AttributeConverter;
//
//@RequiredArgsConstructor
//@Component
//public class Aes256FieldConverter implements AttributeConverter<String, String> {
//
//    private final Aes256Utils aes256Utils;
//
//    @Override
//    public String convertToDatabaseColumn(String attribute) {
//        return aes256Utils.encrypt(attribute);
//    }
//
//    @Override
//    public String convertToEntityAttribute(String dbData) {
//        return aes256Utils.decrypt(dbData);
//    }
//}
