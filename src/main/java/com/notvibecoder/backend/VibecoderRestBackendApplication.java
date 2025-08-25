package com.notvibecoder.backend;

import com.notvibecoder.backend.config.properties.AppProperties;
import com.notvibecoder.backend.config.properties.JwtProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.data.mongodb.config.EnableMongoAuditing;
import org.springframework.validation.annotation.Validated;

@SpringBootApplication
@EnableMongoAuditing
@EnableConfigurationProperties({JwtProperties.class, AppProperties.class})
@Validated
public class VibecoderRestBackendApplication {

    public static void main(String[] args) {
        SpringApplication.run(VibecoderRestBackendApplication.class, args);
    }

}
