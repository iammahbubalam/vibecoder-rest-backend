package com.notvibecoder.backend.security;

import com.notvibecoder.backend.config.properties.AppProperties;
import com.notvibecoder.backend.entity.RefreshToken;
import com.notvibecoder.backend.service.CustomUserDetailsService;
import com.notvibecoder.backend.service.JwtService;
import com.notvibecoder.backend.service.RefreshTokenService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;

@Component
@RequiredArgsConstructor
@Slf4j
public class OAuth2AuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final RefreshTokenService refreshTokenService;
    private final JwtService jwtService;
    private final AppProperties appProperties;
    private final CustomUserDetailsService userDetailsService; // Inject UserDetailsService

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException {
        String targetUrl = determineTargetUrl(request, response, authentication);
        log.debug("Determined target URL: {}", targetUrl);
        if (response.isCommitted()) {
            log.debug("Response has already been committed. Unable to redirect to {}", targetUrl);
            return;
        }
        clearAuthenticationAttributes(request);
        getRedirectStrategy().sendRedirect(request, response, targetUrl);
    }

    @Override
protected String determineTargetUrl(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
    log.info("=== AUTHENTICATION SUCCESS HANDLER CALLED ===");
    log.info("Authentication type: {}", authentication.getClass().getName());
    log.info("Principal type: {}", authentication.getPrincipal().getClass().getName());
    
    UserPrincipal principal;
    
    // Try to cast to UserPrincipal first (from CustomOAuth2UserService)
    try {
        principal = (UserPrincipal) authentication.getPrincipal();
        log.info("Successfully got UserPrincipal for user: {}", principal.getEmail());
    } catch (ClassCastException e) {
        // Fallback: principal is OAuth2User, extract email and load from database
        log.warn("Principal is OAuth2User, not UserPrincipal. Loading user from database.");
        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();
        log.info("OAuth2 User Attributes: {}", oAuth2User.getAttributes());
        String email = oAuth2User.getAttribute("email");
        log.info("Email: {}", email);

        if (email == null) {
            log.info("Could not extract email from OAuth2 principal, redirecting to error page.");
            return UriComponentsBuilder.fromUriString(appProperties.oauth2().redirectUri())
                    .queryParam("error", "EmailNotFound")
                    .build().toUriString();
        }

        try {
            principal = (UserPrincipal) userDetailsService.loadUserByUsername(email);
        } catch (UsernameNotFoundException ex) {
            log.info("User not found in database: {}, redirecting to error page.", email);
            return UriComponentsBuilder.fromUriString(appProperties.oauth2().redirectUri())
                    .queryParam("error", "UserNotFound")
                    .build().toUriString();
        }
    }

    // Generate Access Token using our UserPrincipal
    String accessToken = jwtService.generateToken(principal);
    log.info("JWT Token generated successfully");
    
    // Create Refresh Token and Cookie
    RefreshToken refreshToken = refreshTokenService.createRefreshToken(principal.getId());
    ResponseCookie refreshTokenCookie = refreshTokenService.createRefreshTokenCookie(refreshToken.getToken());
    log.info("Refresh Token created successfully");
    response.addHeader(HttpHeaders.SET_COOKIE, refreshTokenCookie.toString());

    log.info("Successfully authenticated user {}. Redirecting to frontend with access token.", principal.getEmail());

    // Add access token as a query parameter for the frontend to consume
    return UriComponentsBuilder.fromUriString(appProperties.oauth2().redirectUri())
            .queryParam("token", accessToken)
            .build().toUriString();
}
}
