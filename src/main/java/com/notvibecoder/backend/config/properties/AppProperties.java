package com.notvibecoder.backend.config.properties;

import jakarta.validation.constraints.NotEmpty;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

@Data
@ConfigurationProperties(prefix = "app")
@Validated
public class AppProperties {
    
    private Oauth2 oauth2 = new Oauth2();
    private Cors cors = new Cors();
    private Admin admin = new Admin();
    
    @Data
    public static class Oauth2 {
        @NotEmpty
        private String redirectUri;
    }

    @Data
    public static class Cors {
        @NotEmpty
        private String[] allowedOrigins;
    }

    @Data
    public static class Admin {
        @NotEmpty
        private String[] emails;
    }
}
