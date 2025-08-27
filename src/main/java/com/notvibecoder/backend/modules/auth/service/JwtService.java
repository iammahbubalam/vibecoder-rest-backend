package com.notvibecoder.backend.modules.auth.service;

import com.notvibecoder.backend.config.properties.JwtProperties;
import com.notvibecoder.backend.config.properties.JwtSecurityProperties;
import com.notvibecoder.backend.modules.auth.security.UserPrincipal;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import org.springframework.util.Assert;

import java.security.Key;
import java.security.SecureRandom;
import java.util.*;
import java.util.function.Function;
import java.util.stream.Collectors;

@Service
@Slf4j
@RequiredArgsConstructor
public class JwtService {

    private final JwtProperties jwtProperties;
    private final JwtSecurityProperties jwtSecurityProperties;
    private final JwtBlacklistService jwtBlacklistService;
    private final JwtTokenUtil jwtTokenUtil;

    @PostConstruct
    public void validateJwtConfiguration() {
        byte[] keyBytes = Decoders.BASE64.decode(jwtProperties.secret());

        // Validate key strength
        Assert.isTrue(keyBytes.length >= 64,
                "JWT secret must be at least 512 bits (64 bytes) for HS512");

        // Validate entropy (basic check)
        validateKeyEntropy(keyBytes);

        log.info("✅ JWT configuration validated successfully");
    }

    private void validateKeyEntropy(byte[] keyBytes) {
        // Basic entropy check - ensure key isn't all zeros or repetitive
        Set<Byte> uniqueBytes = new HashSet<>();
        for (byte b : keyBytes) {
            uniqueBytes.add(b);
        }

        Assert.isTrue(uniqueBytes.size() >= 16,
                "JWT secret has insufficient entropy - too repetitive");
    }

    // ==================== TOKEN EXTRACTION (DELEGATED) ====================

    public String extractUsername(String token) {
        return jwtTokenUtil.extractUsername(token);
    }

    public String extractJwtId(String token) {
        return jwtTokenUtil.extractJwtId(token);
    }

    public List<String> extractRoles(String token) {
        return jwtTokenUtil.extractRoles(token);
    }

    public String extractUserId(String token) {
        return jwtTokenUtil.extractUserId(token);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        return jwtTokenUtil.extractClaim(token, claimsResolver);
    }

    // ==================== TOKEN GENERATION ====================

    public String generateToken(UserDetails userDetails) {
        Map<String, Object> extraClaims = new HashMap<>();

        // ✅ Add user roles for authorization
        List<String> roles = userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList());
        extraClaims.put("roles", roles);

        // ✅ Add user ID if available
        if (userDetails instanceof UserPrincipal userPrincipal) {
            extraClaims.put("userId", userPrincipal.getId());
            extraClaims.put("email", userPrincipal.getEmail());
        }

        return generateToken(extraClaims, userDetails);
    }

    public String generateToken(Map<String, Object> extraClaims, UserDetails userDetails) {
        String jwtId = UUID.randomUUID().toString();
        Date now = new Date();
        Date expiration = new Date(now.getTime() + jwtProperties.accessToken().expirationMs());

        // Add security claims
        extraClaims.put("iat_timestamp", now.getTime());
        extraClaims.put("token_version", "v2");
        extraClaims.put("security_level", "standard");

        log.debug("Generating secure token for user: {} with JWT ID: {}",
                userDetails.getUsername(), jwtId);

        return Jwts.builder()
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                .setIssuer(jwtSecurityProperties.issuer())
                .setAudience(jwtSecurityProperties.audience())
                .setId(jwtId)
                .setIssuedAt(now)
                .setExpiration(expiration)
                .claim("sessionId", generateSecureSessionId())
                .claim("tokenType", "access")
                .signWith(getSignInKey(), SignatureAlgorithm.HS512)
                .compact();
    }

    // ==================== TOKEN VALIDATION ====================
    private String generateSecureSessionId() {
        SecureRandom secureRandom = new SecureRandom();
        byte[] sessionBytes = new byte[16];
        secureRandom.nextBytes(sessionBytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(sessionBytes);
    }

public boolean isTokenValid(String token) {
    try {
        // Check blacklist first (fastest check)
        if (jwtBlacklistService.isTokenBlacklisted(token)) {
            log.warn("Attempted use of blacklisted token");
            return false;
        }

        // Check expiration using extractClaim method
        Date expiration = extractClaim(token, Claims::getExpiration);
        if (expiration.before(new Date())) {
            log.debug("Token is expired");
            return false;
        }

        // Verify issuer using extractClaim method
        String issuer = extractClaim(token, Claims::getIssuer);
        if (!jwtSecurityProperties.issuer().equals(issuer)) {
            return false;
        }

        // Verify audience using extractClaim method
        String audience = extractClaim(token, Claims::getAudience);
        if (!jwtSecurityProperties.audience().equals(audience)) {
            return false;
        }

        // Verify token type using extractClaim method
        String tokenType = extractClaim(token, claims -> claims.get("tokenType", String.class));
        return "access".equals(tokenType);

    } catch (Exception e) {
        log.error("Token validation error: {}", e.getMessage());
        return false;
    }
}

    // ==================== BLACKLIST OPERATIONS (DELEGATION) ====================

    public void blacklistToken(String token, String reason) {
        jwtBlacklistService.blacklistToken(token, reason);
    }

    public boolean isTokenBlacklisted(String token) {
        return jwtBlacklistService.isTokenBlacklisted(token);
    }

    public void blacklistAllUserTokens(String userId, String reason) {
        jwtBlacklistService.blacklistAllUserTokens(userId, reason);
    }

    // ==================== PRIVATE HELPER METHODS ====================

    private Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(jwtProperties.secret());
        return Keys.hmacShaKeyFor(keyBytes);
    }
}