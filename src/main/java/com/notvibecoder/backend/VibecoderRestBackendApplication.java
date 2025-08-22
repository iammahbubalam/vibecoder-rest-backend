package com.notvibecoder.backend;

import com.notvibecoder.backend.config.properties.AppProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.data.mongodb.config.EnableMongoAuditing;

@SpringBootApplication
@EnableMongoAuditing
@EnableConfigurationProperties({JwtProperties.class, AppProperties.class})
public class VibecoderRestBackendApplication {

	public static void main(String[] args) {
		SpringApplication.run(VibecoderRestBackendApplication.class, args);
	}

}
