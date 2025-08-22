package com.notvibecoder.backend.config.properties;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "app")
@Data
public class AppProperties {
    private final Oauth2 oauth2 = new Oauth2();
    private final Cors cors = new Cors();

    @Data
    public static class Oauth2 {
        private String redirectUri;
    }

    @Data
    public static class Cors {
        private String[] allowedOrigins;
    }
}
