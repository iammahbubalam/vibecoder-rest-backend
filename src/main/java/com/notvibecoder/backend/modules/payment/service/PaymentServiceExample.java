package com.notvibecoder.backend.modules.payment.service;

import com.notvibecoder.backend.modules.admin.constants.SecurityConstants;
import com.notvibecoder.backend.modules.payment.entity.PaymentRequest;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PostFilter;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * Payment Service demonstrating service-layer security
 * 
 * Shows different types of method-level security:
 * - @PreAuthorize: Check before method execution
 * - @PostAuthorize: Check after method execution (with return value)
 * - @PostFilter: Filter returned collections based on permissions
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class PaymentServiceExample {

    // ==================== ADMIN ONLY METHODS ====================
    
    /**
     * Verify payment - admin only
     */
    @PreAuthorize(SecurityConstants.CAN_VERIFY_PAYMENTS)
    public PaymentRequest verifyPayment(String paymentId, String adminNote) {
        log.info("Admin verifying payment: {}", paymentId);
        // Implementation here
        return new PaymentRequest();
    }

    /**
     * Get all payment requests - admin only
     */
    @PreAuthorize(SecurityConstants.HAS_ROLE_ADMIN)
    public List<PaymentRequest> getAllPaymentRequests() {
        log.info("Admin retrieving all payment requests");
        // Implementation here
        return List.of();
    }

    // ==================== USER ACCESS WITH OWNERSHIP CHECK ====================
    
    /**
     * Get user payments - user can see their own, admin can see any
     */
    @PreAuthorize(SecurityConstants.CAN_ACCESS_USER_DATA)
    public List<PaymentRequest> getUserPayments(String userId) {
        log.info("Retrieving payments for user: {}", userId);
        // Implementation here
        return List.of();
    }

    /**
     * Get payment details - only if user owns it or is admin
     */
    @PostAuthorize("@securityService.isAdmin() or returnObject.userId == authentication.principal.id")
    public PaymentRequest getPaymentDetails(String paymentId) {
        log.info("Retrieving payment details: {}", paymentId);
        // Implementation here - return payment regardless, security filters afterward
        return new PaymentRequest();
    }

    // ==================== FILTERED RESULTS ====================
    
    /**
     * Get all payments with filtering - users only see their own, admins see all
     * PostFilter is applied after method execution to filter the returned list
     */
    @PostFilter("@securityService.isAdmin() or filterObject.userId == authentication.principal.id")
    public List<PaymentRequest> getFilteredPayments() {
        log.info("Retrieving filtered payments");
        // Implementation returns all payments, Spring Security filters them
        return List.of();
    }

    // ==================== BUSINESS LOGIC WITH SECURITY ====================
    
    /**
     * Submit payment request - any authenticated user
     */
    @PreAuthorize(SecurityConstants.IS_AUTHENTICATED)
    public PaymentRequest submitPaymentRequest(PaymentRequest request, String userId) {
        // Additional security check within method
        if (!isCurrentUserOrAdmin(userId)) {
            throw new SecurityException("Cannot submit payment for another user");
        }
        
        log.info("User {} submitting payment request", userId);
        // Implementation here
        return request;
    }

    /**
     * Cancel payment request - only owner or admin
     */
    @PreAuthorize("@securityService.isAdmin() or @paymentService.isPaymentOwner(#paymentId, authentication.principal.id)")
    public void cancelPaymentRequest(String paymentId) {
        log.info("Cancelling payment request: {}", paymentId);
        // Implementation here
    }

    // ==================== HELPER METHODS ====================
    
    /**
     * Check if payment belongs to current user
     * This method can be used in @PreAuthorize expressions
     */
    public boolean isPaymentOwner(String paymentId, String userId) {
        // Implementation would check database
        return true; // Placeholder
    }

    private boolean isCurrentUserOrAdmin(String userId) {
        // Implementation would check current user
        return true; // Placeholder
    }
}
