package com.notvibecoder.backend.security;

import com.notvibecoder.backend.config.properties.AppProperties;
import com.notvibecoder.backend.entity.RefreshToken;
import com.notvibecoder.backend.service.RefreshTokenService;
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

@Component
@RequiredArgsConstructor
@Slf4j
public class OAuth2AuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final RefreshTokenService refreshTokenService;
    private final AppProperties appProperties;

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
        UserPrincipal userPrincipal = (UserPrincipal) authentication.getPrincipal();
        RefreshToken refreshToken = refreshTokenService.createRefreshToken(userPrincipal.getId());

        ResponseCookie refreshTokenCookie = refreshTokenService.createRefreshTokenCookie(refreshToken.getToken());
        response.addHeader(HttpHeaders.SET_COOKIE, refreshTokenCookie.toString());

        log.info("Successfully authenticated user {}. Redirecting to frontend.", userPrincipal.getUsername());
        return UriComponentsBuilder.fromUriString(appProperties.getOauth2().getRedirectUri()).build().toUriString();
    }
}

