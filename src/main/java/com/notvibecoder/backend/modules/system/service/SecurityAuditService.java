package com.notvibecoder.backend.modules.system.service;

import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

@Service
@Slf4j
public class SecurityAuditService {

    public void logTokenCreation(String userId, HttpServletRequest request, boolean hadExistingSession) {
        if (request == null) return;

        String clientIp = getClientIp(request);
        String userAgent = request.getHeader("User-Agent");

        if (hadExistingSession) {
            log.warn("SECURITY_AUDIT: New device login terminated previous session - User: {}, IP: {}, UserAgent: {}",
                    userId, clientIp, userAgent);
        } else {
            log.info("SECURITY_AUDIT: Single session created - User: {}, IP: {}, UserAgent: {}",
                    userId, clientIp, userAgent);
        }
    }

    public void logTokenUsage(String userId, HttpServletRequest request) {
        if (request == null) return;

        String clientIp = getClientIp(request);
        log.info("SECURITY_AUDIT: Session token used - User: {}, IP: {}", userId, clientIp);
    }

    private String getClientIp(HttpServletRequest request) {
        String xfHeader = request.getHeader("X-Forwarded-For");
        if (StringUtils.hasText(xfHeader)) {
            return xfHeader.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
}