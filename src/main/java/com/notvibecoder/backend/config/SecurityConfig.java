package com.notvibecoder.backend.config;

import com.notvibecoder.backend.security.CustomOAuth2UserService;
import com.notvibecoder.backend.security.JwtAuthenticationFilter;
import com.notvibecoder.backend.security.OAuth2AuthenticationSuccessHandler;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
@Slf4j
public class SecurityConfig {

    private final CustomOAuth2UserService customOAuth2UserService;
    private final OAuth2AuthenticationSuccessHandler oAuth2AuthenticationSuccessHandler;
    private final JwtAuthenticationFilter jwtAuthenticationFilter;

@Bean
public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    System.out.println("=== SecurityFilterChain BEAN CREATION STARTED ===");
    log.info("=== SecurityFilterChain BEAN CREATION STARTED ===");
    log.info("Configuring Security with CustomOAuth2UserService: {}", customOAuth2UserService.getClass().getName());
    
    http
            .csrf(AbstractHttpConfigurer::disable)
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .headers(headers -> headers
                    .httpStrictTransportSecurity(hstsConfig -> hstsConfig
                            .includeSubDomains(true)
                            .maxAgeInSeconds(31536000))
                    .contentSecurityPolicy(cspConfig -> cspConfig
                            .policyDirectives("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; object-src 'none'; frame-ancestors 'none';"))
                    .frameOptions(HeadersConfigurer.FrameOptionsConfig::deny)
            )
            .authorizeHttpRequests(auth -> auth
                    .requestMatchers("/api/v1/auth/**", "/oauth2/**", "/login/**").permitAll()
                    .anyRequest().authenticated()
            )
            .oauth2Login(oauth2 -> oauth2
        .authorizationEndpoint(endpoint -> endpoint.baseUri("/oauth2/authorize"))
        .userInfoEndpoint(userInfo -> userInfo
                .userService(customOAuth2UserService)
        )
        .successHandler(oAuth2AuthenticationSuccessHandler)
        .failureHandler((request, response, exception) -> {
            log.info("OAuth2 authentication failed", exception);
            response.sendRedirect("/api/v1/auth/login?error=oauth2_failed");
        })
)
            .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);
    
    log.info("=== SecurityFilterChain BEAN CREATION COMPLETED ===");
    return http.build();
}
}