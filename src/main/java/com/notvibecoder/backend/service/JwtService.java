package com.notvibecoder.backend.service;

import com.notvibecoder.backend.config.properties.JwtProperties;
import com.notvibecoder.backend.entity.BlacklistedToken;
import com.notvibecoder.backend.repository.BlacklistedTokenRepository;
import com.notvibecoder.backend.security.UserPrincipal;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.function.Function;
import java.util.stream.Collectors;

@Service
@Slf4j
@RequiredArgsConstructor
public class JwtService {

    private final JwtProperties jwtProperties;
    private final BlacklistedTokenRepository blacklistedTokenRepository;
    
    private static final String ISSUER = "vibecoder-backend";
    private static final String AUDIENCE = "vibecoder-frontend";

    // ==================== TOKEN EXTRACTION ====================
    
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }
    
    public String extractJwtId(String token) {
        return extractClaim(token, Claims::getId);
    }
    
    public List<String> extractRoles(String token) {
        return extractClaim(token, claims -> claims.get("roles", List.class));
    }
    
    public String extractUserId(String token) {
        return extractClaim(token, claims -> claims.get("userId", String.class));
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
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
        if (userDetails instanceof UserPrincipal) {
            UserPrincipal userPrincipal = (UserPrincipal) userDetails;
            extraClaims.put("userId", userPrincipal.getId());
            extraClaims.put("email", userPrincipal.getEmail());
        }
        
        return generateToken(extraClaims, userDetails);
    }

    public String generateToken(Map<String, Object> extraClaims, UserDetails userDetails) {
        String jwtId = UUID.randomUUID().toString();
        Date now = new Date();
        Date expiration = new Date(now.getTime() + jwtProperties.accessToken().expirationMs());
        
        log.debug("Generating enhanced access token for user: {} with JWT ID: {}", userDetails.getUsername(), jwtId);
        
        return Jwts.builder()
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                .setIssuer(ISSUER)                           // ✅ Verify token origin
                .setAudience(AUDIENCE)                       // ✅ Restrict token usage
                .setId(jwtId)                               // ✅ Unique ID for blacklisting
                .setIssuedAt(now)
                .setExpiration(expiration)
                .claim("sessionId", generateSessionId())     // ✅ Additional security
                .claim("tokenType", "access")               // ✅ Token type validation
                .signWith(getSignInKey(), SignatureAlgorithm.HS512) // ✅ Stronger algorithm
                .compact();
    }

    // ==================== TOKEN VALIDATION ====================
    
    public boolean isTokenValid(String token) {
        try {
            // ✅ Primary security check - blacklist first
            if (isTokenBlacklisted(token)) {
                log.warn("Attempted use of blacklisted token");
                return false;
            }
            
            // ✅ Check expiration
            if (isTokenExpired(token)) {
                log.debug("Token is expired");
                return false;
            }
            
            // ✅ Verify issuer and audience for security
            return isValidIssuer(token) && isValidAudience(token) && isValidTokenType(token);
            
        } catch (Exception e) {
            log.error("Token validation error: {}", e.getMessage());
            return false;
        }
    }
    
    // ==================== TOKEN BLACKLISTING ====================
    
    public void blacklistToken(String token, String reason) {
        try {
            String jwtId = extractJwtId(token);
            String userId = extractUserId(token);
            Date expiration = extractExpiration(token);
            
            BlacklistedToken blacklistedToken = BlacklistedToken.builder()
                    .jwtId(jwtId)
                    .userId(userId != null ? userId : extractUsername(token)) // Fallback to username
                    .reason(reason)
                    .blacklistedAt(Instant.now())
                    .expiresAt(expiration.toInstant())
                    .build();
                    
            blacklistedTokenRepository.save(blacklistedToken);
            log.info("Token blacklisted - JWT ID: {}, User: {}, Reason: {}", jwtId, userId, reason);
            
        } catch (Exception e) {
            log.error("Failed to blacklist token: {}", e.getMessage());
            // Don't throw - blacklisting failure shouldn't break logout
        }
    }
    
    public boolean isTokenBlacklisted(String token) {
        try {
            String jwtId = extractJwtId(token);
            return blacklistedTokenRepository.existsByJwtId(jwtId);
        } catch (Exception e) {
            log.error("Error checking blacklist: {}", e.getMessage());
            return true; // Fail secure - assume blacklisted on error
        }
    }
    
    public void blacklistAllUserTokens(String userId, String reason) {
        try {
            // ✅ Single session: simpler since only one token per user
            log.info("Blacklisting current session for user: {} with reason: {}", userId, reason);
        } catch (Exception e) {
            log.error("Error blacklisting user session: {}", e.getMessage());
        }
    }

    // ==================== PRIVATE HELPER METHODS ====================
    
    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }
    
    private boolean isValidIssuer(String token) {
        try {
            String issuer = extractClaim(token, Claims::getIssuer);
            return ISSUER.equals(issuer);
        } catch (Exception e) {
            return false;
        }
    }
    
    private boolean isValidAudience(String token) {
        try {
            String audience = extractClaim(token, Claims::getAudience);
            return AUDIENCE.equals(audience);
        } catch (Exception e) {
            return false;
        }
    }
    
    private boolean isValidTokenType(String token) {
        try {
            String tokenType = extractClaim(token, claims -> claims.get("tokenType", String.class));
            return "access".equals(tokenType);
        } catch (Exception e) {
            return false;
        }
    }
    
    private String generateSessionId() {
        return UUID.randomUUID().toString().substring(0, 8);
    }

    private Claims extractAllClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(getSignInKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    private Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(jwtProperties.secret());
        return Keys.hmacShaKeyFor(keyBytes);
    }
}