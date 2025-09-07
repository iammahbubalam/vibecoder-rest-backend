package com.notvibecoder.backend.modules.auth.security;

import com.notvibecoder.backend.config.properties.AppProperties;
import com.notvibecoder.backend.modules.auth.service.JwtService;
import com.notvibecoder.backend.modules.auth.service.RefreshTokenService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;

/**
 * Handles successful OAuth2 authentication by generating JWT tokens and redirecting users.
 * Expects the principal to be a UserPrincipal instance from CustomOAuth2UserService.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class OAuth2AuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final RefreshTokenService refreshTokenService;
    private final JwtService jwtService;
    private final AppProperties appProperties;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException {
        String targetUrl = determineTargetUrl(request, response, authentication);

        if (response.isCommitted()) {
            log.debug("Response already committed. Cannot redirect to: {}", targetUrl);
            return;
        }

        clearAuthenticationAttributes(request);
        getRedirectStrategy().sendRedirect(request, response, targetUrl);
    }

    @Override
    protected String determineTargetUrl(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) {
        log.info("Processing OAuth2 authentication success");

        try {
            UserPrincipal principal = extractUserPrincipal(authentication);
            return buildSuccessRedirectUrl(request, response, principal);

        } catch (Exception e) {
            log.error("Error processing OAuth2 authentication", e);
            return buildErrorRedirectUrl();
        }
    }


    /**
     * Extracts UserPrincipal from authentication object.
     * Handles both UserPrincipal (expected) and any OAuth2User types during transition.
     */
    private UserPrincipal extractUserPrincipal(Authentication authentication) {
        Object principal = authentication.getPrincipal();

        if (principal instanceof UserPrincipal userPrincipal) {
            log.info("Successfully extracted UserPrincipal for user: {}", userPrincipal.getEmail());
            return userPrincipal;
        }

        log.error("Expected UserPrincipal but got: {}. Check CustomOAuth2UserService configuration.",
                principal.getClass().getSimpleName());
        throw new IllegalStateException("Invalid principal type: " + principal.getClass().getSimpleName());
    }

    /**
     * Generates tokens and builds success redirect URL.
     */
    private String buildSuccessRedirectUrl(HttpServletRequest request, HttpServletResponse response, UserPrincipal principal) {
        try {
            // Generate access token
            String accessToken = jwtService.generateToken(principal);
            log.debug("Generated JWT access token for user: {}", principal.getEmail());
            ResponseCookie refreshTokenCookie = refreshTokenService.createRefreshTokenCookie(principal.getId(), request);
            response.addHeader(HttpHeaders.SET_COOKIE, refreshTokenCookie.toString());
            log.debug("Created refresh token cookie for user: {}", principal.getEmail());

            // Build redirect URL with access token
            String redirectUrl = UriComponentsBuilder
                    .fromUriString(appProperties.getOauth2().getRedirectUri())
                    .queryParam("token", accessToken)
                    .build()
                    .toUriString();

            log.info("OAuth2 authentication successful for user: {}. Redirecting to: {}",
                    principal.getEmail(), appProperties.getOauth2().getRedirectUri());

            return redirectUrl;

        } catch (Exception e) {
            log.error("Error generating tokens for user: {}", principal.getEmail(), e);
            throw new RuntimeException("Token generation failed", e);
        }
    }

    /**
     * Builds error redirect URL with error parameter.
     */
    private String buildErrorRedirectUrl() {
        String errorUrl = UriComponentsBuilder
                .fromUriString(appProperties.getOauth2().getRedirectUri())
                .queryParam("error", "ProcessingError")
                .build()
                .toUriString();

        log.warn("Redirecting to error page with code: {}", "ProcessingError");
        return errorUrl;
    }
}