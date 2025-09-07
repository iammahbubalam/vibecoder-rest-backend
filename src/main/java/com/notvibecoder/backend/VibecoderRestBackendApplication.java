package com.notvibecoder.backend;

import com.notvibecoder.backend.config.properties.AppProperties;
import com.notvibecoder.backend.config.properties.JwtProperties;
import com.notvibecoder.backend.config.properties.JwtSecurityProperties;
import io.github.cdimascio.dotenv.Dotenv;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.data.mongodb.config.EnableMongoAuditing;
import org.springframework.validation.annotation.Validated;

@SpringBootApplication
@EnableMongoAuditing
@EnableConfigurationProperties({JwtProperties.class, AppProperties.class, JwtSecurityProperties.class})
@Validated
public class VibecoderRestBackendApplication {

    public static void main(String[] args) {
        // Load .env file before Spring Boot starts
        try {
            Dotenv dotenv = Dotenv.configure()
                    .directory("./")
                    .ignoreIfMalformed()
                    .ignoreIfMissing()
                    .load();
            
            System.out.println("DEBUG: .env file loaded successfully");
            System.out.println("DEBUG: Number of entries: " + dotenv.entries().size());
            
            // Set system properties from .env file
            dotenv.entries().forEach(entry -> {
                System.setProperty(entry.getKey(), entry.getValue());
                System.out.println("DEBUG: Set system property: " + entry.getKey() + " = " + 
                    (entry.getKey().contains("SECRET") ? "***HIDDEN***" : entry.getValue()));
            });
            
            // Map environment variables to Spring Boot property names
            String jwtSecret = dotenv.get("JWT_SECRET");
            String jwtAccessExpiration = dotenv.get("JWT_ACCESS_TOKEN_EXPIRATION");
            String jwtRefreshExpiration = dotenv.get("JWT_REFRESH_TOKEN_EXPIRATION");
            String mongoUri = dotenv.get("MONGODB_URI");
            String mongoDatabase = dotenv.get("MONGODB_DATABASE");
            String googleClientId = dotenv.get("GOOGLE_CLIENT_ID");
            String googleClientSecret = dotenv.get("GOOGLE_CLIENT_SECRET");
            String frontendUrl = dotenv.get("FRONTEND_URL");
            String adminEmail = dotenv.get("ADMIN_EMAIL");
            String environment = dotenv.get("ENVIRONMENT");
            
            if (jwtSecret != null) {
                System.setProperty("jwt.secret", jwtSecret);
                System.out.println("DEBUG: Set jwt.secret property");
            }
            if (jwtAccessExpiration != null) {
                System.setProperty("jwt.access-token.expiration-ms", jwtAccessExpiration);
                System.out.println("DEBUG: Set jwt.access-token.expiration-ms property");
            }
            if (jwtRefreshExpiration != null) {
                System.setProperty("jwt.refresh-token.expiration-ms", jwtRefreshExpiration);
                System.out.println("DEBUG: Set jwt.refresh-token.expiration-ms property");
            }
            if (mongoUri != null) {
                System.setProperty("spring.data.mongodb.uri", mongoUri);
                System.out.println("DEBUG: Set spring.data.mongodb.uri property");
            }
            if (mongoDatabase != null) {
                System.setProperty("spring.data.mongodb.database", mongoDatabase);
                System.out.println("DEBUG: Set spring.data.mongodb.database property");
            }
            if (googleClientId != null) {
                System.setProperty("spring.security.oauth2.client.registration.google.client-id", googleClientId);
                System.out.println("DEBUG: Set google client-id property");
            }
            if (googleClientSecret != null) {
                System.setProperty("spring.security.oauth2.client.registration.google.client-secret", googleClientSecret);
                System.out.println("DEBUG: Set google client-secret property");
            }
            if (frontendUrl != null) {
                System.setProperty("app.oauth2.redirect-uri", frontendUrl + "/oauth2/redirect");
                System.setProperty("app.cors.allowed-origins", frontendUrl);
                System.out.println("DEBUG: Set frontend URL properties");
            }
            if (adminEmail != null) {
                System.setProperty("app.admin.emails", adminEmail);
                System.out.println("DEBUG: Set admin email property");
            }
            if (environment != null) {
                System.setProperty("spring.profiles.active", environment);
                System.out.println("DEBUG: Set spring.profiles.active property");
            }
            
            // Verify specific properties
            System.out.println("DEBUG: jwt.secret system property: " + 
                (System.getProperty("jwt.secret") != null ? "SET" : "NOT SET"));
            System.out.println("DEBUG: spring.data.mongodb.uri system property: " + 
                (System.getProperty("spring.data.mongodb.uri") != null ? "SET" : "NOT SET"));
            
        } catch (Exception e) {
            System.err.println("Warning: Could not load .env file: " + e.getMessage());
            e.printStackTrace();
        }
        
        SpringApplication.run(VibecoderRestBackendApplication.class, args);
    }

}
