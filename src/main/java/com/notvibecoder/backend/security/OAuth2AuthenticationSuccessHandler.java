package com.notvibecoder.backend.security;

import com.notvibecoder.backend.config.properties.AppProperties;
import com.notvibecoder.backend.entity.RefreshToken;
import com.notvibecoder.backend.service.JwtService;
import com.notvibecoder.backend.service.RefreshTokenService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetailsService;
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
    private final UserDetailsService userDetailsService; // Inject UserDetailsService

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException {
        String targetUrl = determineTargetUrl(request, response, authentication);
        if (response.isCommitted()) {
            log.debug("Response has already been committed. Unable to redirect to {}", targetUrl);
            return;
        }
        clearAuthenticationAttributes(request);
        getRedirectStrategy().sendRedirect(request, response, targetUrl);
    }

    @Override
    protected String determineTargetUrl(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        // The principal is the source of truth for the authenticated user's identity.
        // For OIDC providers like Google, this will be an OidcUser.
        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();
        String email = oAuth2User.getAttribute("email");

        if (email == null) {
            log.error("Could not extract email from OAuth2 principal, redirecting to error page.");
            return UriComponentsBuilder.fromUriString(appProperties.oauth2().redirectUri())
                    .queryParam("error", "EmailNotFound")
                    .build().toUriString();
        }

        // Use the email to load our full UserDetails object, which is a UserPrincipal.
        // This ensures we have the correct roles and user ID from our database.
        UserPrincipal principal = (UserPrincipal) userDetailsService.loadUserByUsername(email);

        // Generate Access Token using our full UserPrincipal
        String accessToken = jwtService.generateToken(principal);

        // Create Refresh Token and Cookie
        RefreshToken refreshToken = refreshTokenService.createRefreshToken(principal.getId());
        ResponseCookie refreshTokenCookie = refreshTokenService.createRefreshTokenCookie(refreshToken.getToken());
        response.addHeader(HttpHeaders.SET_COOKIE, refreshTokenCookie.toString());

        log.info("Successfully authenticated user {}. Redirecting to frontend with access token.", email);

        // Add access token as a query parameter for the frontend to consume
        return UriComponentsBuilder.fromUriString(appProperties.oauth2().redirectUri())
                .queryParam("token", accessToken)
                .build().toUriString();
    }
}
