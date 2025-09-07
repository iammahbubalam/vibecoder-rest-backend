package com.notvibecoder.backend.modules.order.controller;

import com.notvibecoder.backend.core.dto.ApiResponse;
import com.notvibecoder.backend.core.exception.ValidationException;
import com.notvibecoder.backend.modules.auth.security.UserPrincipal;
import com.notvibecoder.backend.modules.order.dto.CreateOrderRequest;
import com.notvibecoder.backend.modules.order.dto.PaymentApprovalRequest;
import com.notvibecoder.backend.modules.order.dto.PaymentRejectionRequest;
import com.notvibecoder.backend.modules.order.dto.PaymentSubmissionRequest;
import com.notvibecoder.backend.modules.order.dto.RevokeAccessRequest;
import com.notvibecoder.backend.modules.order.entity.Order;
import com.notvibecoder.backend.modules.order.entity.OrderStatus;
import com.notvibecoder.backend.modules.order.entity.PaymentMethod;
import com.notvibecoder.backend.modules.order.service.OrderService;
import com.notvibecoder.backend.modules.system.constants.SecurityConstants;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.math.BigDecimal;
import java.util.List;

/**
 * Order Controller - Complete order lifecycle management
 * 
 * Provides endpoints for:
 * - Order creation and management
 * - Payment submission and verification
 * - Administrative order operations
 * - Order search and analytics
 * 
 * Security:
 * - User endpoints: Require authentication and user ownership validation
 * - Admin endpoints: Require ADMIN role
 * - Proper input validation and error handling
 * 
 * @author Senior Backend Engineer
 * @version 1.0
 */
@RestController
@RequestMapping("/api/v1/orders")
@RequiredArgsConstructor
@Slf4j
public class OrderController {

    private final OrderService orderService;

    // ==================== USER ORDER OPERATIONS ====================

    /**
     * Create a new order for a course
     * POST /api/v1/orders
     * 
     * @param request Order creation request with course ID
     * @param principal Authenticated user
     * @return Created order details
     */
    @PostMapping
    @PreAuthorize(SecurityConstants.ORDER_CREATE)
    public ResponseEntity<ApiResponse<Order>> createOrder(
            @Valid @RequestBody CreateOrderRequest request,
            @AuthenticationPrincipal UserPrincipal principal) {

        log.info("User {} creating order for course: {}", principal.getId(), request.getCourseId());

        try {
            Order createdOrder = orderService.createOrder(principal.getId(), request.getCourseId());
            
            log.info("Order created successfully: {} for user: {} and course: {}", 
                    createdOrder.getId(), principal.getId(), request.getCourseId());

            return ResponseEntity.status(HttpStatus.CREATED)
                    .body(ApiResponse.success("Order created successfully", createdOrder));

        } catch (ValidationException e) {
            log.warn("Validation error creating order for user {}: {}", principal.getId(), e.getMessage());
            return ResponseEntity.badRequest()
                    .body(ApiResponse.error("Order creation failed: " + e.getMessage(), "VALIDATION_ERROR"));
        } catch (Exception e) {
            log.error("Error creating order for user {}: {}", principal.getId(), e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponse.error("Failed to create order", "ORDER_CREATION_ERROR"));
        }
    }

    /**
     * Submit payment information for an order
     * PUT /api/v1/orders/{orderId}/payment
     * 
     * @param orderId Order ID
     * @param request Payment submission details
     * @param principal Authenticated user
     * @return Updated order with payment info
     */
    @PutMapping("/{orderId}/payment")
    @PreAuthorize(SecurityConstants.ORDER_MANAGE_OWN)
    public ResponseEntity<ApiResponse<Order>> submitPayment(
            @PathVariable String orderId,
            @Valid @RequestBody PaymentSubmissionRequest request,
            @AuthenticationPrincipal UserPrincipal principal) {

        log.info("User {} submitting payment for order: {} with transaction: {}", 
                principal.getId(), orderId, request.getTransactionId());

        try {
            // Verify order ownership by attempting to get the order
            orderService.getOrder(orderId, principal.getId());
            
            Order updatedOrder = orderService.submitPayment(
                    orderId, 
                    request.getPaymentMethod(), 
                    request.getTransactionId(),
                    request.getPhoneNumber(), 
                    request.getPaymentNote()
            );

            log.info("Payment submitted successfully for order: {} by user: {}", orderId, principal.getId());

            return ResponseEntity.ok(
                    ApiResponse.success("Payment submitted successfully. Awaiting admin verification.", updatedOrder));

        } catch (ValidationException e) {
            log.warn("Validation error submitting payment for order {}: {}", orderId, e.getMessage());
            return ResponseEntity.badRequest()
                    .body(ApiResponse.error("Payment submission failed: " + e.getMessage(), "VALIDATION_ERROR"));
        } catch (Exception e) {
            log.error("Error submitting payment for order {}: {}", orderId, e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponse.error("Failed to submit payment", "PAYMENT_SUBMISSION_ERROR"));
        }
    }

    /**
     * Cancel a pending order
     * PUT /api/v1/orders/{orderId}/cancel
     * 
     * @param orderId Order ID to cancel
     * @param principal Authenticated user
     * @return Cancelled order details
     */
    @PutMapping("/{orderId}/cancel")
    @PreAuthorize(SecurityConstants.ORDER_MANAGE_OWN)
    public ResponseEntity<ApiResponse<Order>> cancelOrder(
            @PathVariable String orderId,
            @AuthenticationPrincipal UserPrincipal principal) {

        log.info("User {} attempting to cancel order: {}", principal.getId(), orderId);

        try {
            Order cancelledOrder = orderService.cancelOrder(orderId, principal.getId());
            
            log.info("Order cancelled successfully: {} by user: {}", orderId, principal.getId());

            return ResponseEntity.ok(
                    ApiResponse.success("Order cancelled successfully", cancelledOrder));

        } catch (ValidationException e) {
            log.warn("Validation error cancelling order {}: {}", orderId, e.getMessage());
            return ResponseEntity.badRequest()
                    .body(ApiResponse.error("Order cancellation failed: " + e.getMessage(), "VALIDATION_ERROR"));
        } catch (Exception e) {
            log.error("Error cancelling order {}: {}", orderId, e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponse.error("Failed to cancel order", "ORDER_CANCELLATION_ERROR"));
        }
    }

    /**
     * Get specific order details
     * GET /api/v1/orders/{orderId}
     * 
     * @param orderId Order ID
     * @param principal Authenticated user
     * @return Order details
     */
    @GetMapping("/{orderId}")
    @PreAuthorize(SecurityConstants.ORDER_VIEW_OWN)
    public ResponseEntity<ApiResponse<Order>> getOrder(
            @PathVariable String orderId,
            @AuthenticationPrincipal UserPrincipal principal) {

        log.debug("User {} retrieving order: {}", principal.getId(), orderId);

        try {
            Order order = orderService.getOrder(orderId, principal.getId());
            
            return ResponseEntity.ok(
                    ApiResponse.success("Order retrieved successfully", order));

        } catch (ValidationException e) {
            log.warn("Validation error retrieving order {}: {}", orderId, e.getMessage());
            return ResponseEntity.badRequest()
                    .body(ApiResponse.error("Order retrieval failed: " + e.getMessage(), "VALIDATION_ERROR"));
        } catch (Exception e) {
            log.error("Error retrieving order {}: {}", orderId, e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(ApiResponse.error("Order not found", "ORDER_NOT_FOUND"));
        }
    }

    /**
     * Get user's own orders with search capability
     * GET /api/v1/orders/my-orders
     */
    @GetMapping("/my-orders")
    @PreAuthorize(SecurityConstants.ORDER_VIEW_OWN)
    public ResponseEntity<ApiResponse<Page<Order>>> getMyOrders(
            @RequestParam(required = false) OrderStatus status,
            @RequestParam(required = false) String courseId,
            @RequestParam(required = false) String searchText,
            @RequestParam(required = false) String dateFrom,
            @RequestParam(required = false) String dateTo,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size,
            @AuthenticationPrincipal UserPrincipal principal) {

        String userId = principal.getId();

        log.info("User {} searching their orders with filters - status: {}, courseId: {}, searchText: {}, dateFrom: {}, dateTo: {}",
                userId, status, courseId, searchText, dateFrom, dateTo);

        // Validate pagination parameters
        if (page < 0 || size <= 0 || size > 50) {
            return ResponseEntity.badRequest()
                    .body(ApiResponse.<Page<Order>>builder()
                            .success(false)
                            .message("Invalid pagination parameters. Page must be >= 0, size must be 1-50")
                            .build());
        }

        Pageable pageable = PageRequest.of(page, size,
                org.springframework.data.domain.Sort.by(
                        org.springframework.data.domain.Sort.Direction.DESC, "createdAt"));

        try {
            // Users can only search their own orders
            Page<Order> orders = orderService.searchOrders(
                    userId, courseId, status, null, // No payment method filter for users
                    null, null, searchText, // No transaction ID or phone filter for users
                    dateFrom, dateTo, pageable
            );

            return ResponseEntity.ok(
                    ApiResponse.<Page<Order>>builder()
                            .success(true)
                            .message("Your orders retrieved successfully")
                            .data(orders)
                            .build()
            );

        } catch (Exception e) {
            log.error("Error retrieving user orders for user {}: {}", userId, e.getMessage(), e);
            return ResponseEntity.badRequest()
                    .body(ApiResponse.<Page<Order>>builder()
                            .success(false)
                            .message("Failed to retrieve your orders: " + e.getMessage())
                            .build());
        }
    }

    // ==================== ADMIN ORDER MANAGEMENT ====================

    /**
     * Approve payment and grant course access
     * PUT /api/v1/orders/{orderId}/approve
     * 
     * @param orderId Order ID to approve
     * @param request Approval details
     * @param principal Admin user
     * @return Approved order details
     */
    @PutMapping("/{orderId}/approve")
    @PreAuthorize(SecurityConstants.ORDER_ADMIN_MANAGE)
    public ResponseEntity<ApiResponse<Order>> approvePayment(
            @PathVariable String orderId,
            @Valid @RequestBody PaymentApprovalRequest request,
            @AuthenticationPrincipal UserPrincipal principal) {

        log.info("Admin {} approving payment for order: {}", principal.getId(), orderId);

        try {
            Order approvedOrder = orderService.approvePayment(orderId, principal.getId(), request.getAdminNote());
            
            log.info("Payment approved successfully for order: {} by admin: {}", orderId, principal.getId());

            return ResponseEntity.ok(
                    ApiResponse.success("Payment approved successfully. Course access granted.", approvedOrder));

        } catch (ValidationException e) {
            log.warn("Validation error approving payment for order {}: {}", orderId, e.getMessage());
            return ResponseEntity.badRequest()
                    .body(ApiResponse.error("Payment approval failed: " + e.getMessage(), "VALIDATION_ERROR"));
        } catch (Exception e) {
            log.error("Error approving payment for order {}: {}", orderId, e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponse.error("Failed to approve payment", "PAYMENT_APPROVAL_ERROR"));
        }
    }

    /**
     * Reject payment with reason
     * PUT /api/v1/orders/{orderId}/reject
     * 
     * @param orderId Order ID to reject
     * @param request Rejection details
     * @param principal Admin user
     * @return Rejected order details
     */
    @PutMapping("/{orderId}/reject")
    @PreAuthorize(SecurityConstants.ORDER_ADMIN_MANAGE)
    public ResponseEntity<ApiResponse<Order>> rejectPayment(
            @PathVariable String orderId,
            @Valid @RequestBody PaymentRejectionRequest request,
            @AuthenticationPrincipal UserPrincipal principal) {

        log.info("Admin {} rejecting payment for order: {}", principal.getId(), orderId);

        try {
            Order rejectedOrder = orderService.rejectPayment(orderId, principal.getId(), request.getRejectionReason());
            
            log.info("Payment rejected successfully for order: {} by admin: {}", orderId, principal.getId());

            return ResponseEntity.ok(
                    ApiResponse.success("Payment rejected successfully", rejectedOrder));

        } catch (ValidationException e) {
            log.warn("Validation error rejecting payment for order {}: {}", orderId, e.getMessage());
            return ResponseEntity.badRequest()
                    .body(ApiResponse.error("Payment rejection failed: " + e.getMessage(), "VALIDATION_ERROR"));
        } catch (Exception e) {
            log.error("Error rejecting payment for order {}: {}", orderId, e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponse.error("Failed to reject payment", "PAYMENT_REJECTION_ERROR"));
        }
    }

    /**
     * Advanced order search endpoint for admin users
     * GET /api/v1/orders/search
     * 
     * Query Parameters (all optional):
     * - userId: Filter by specific user ID
     * - courseId: Filter by specific course ID  
     * - status: Filter by order status (PENDING, SUBMITTED, VERIFIED, REJECTED)
     * - paymentMethod: Filter by payment method (BKASH, NAGAD, ROCKET, BANK_TRANSFER)
     * - transactionId: Search by transaction ID (partial match)
     * - phoneNumber: Search by phone number (partial match)
     * - searchText: Text search across user name, email, course title, instructor
     * - dateFrom: Start date filter (format: YYYY-MM-DD or YYYY-MM-DDTHH:mm:ssZ)
     * - dateTo: End date filter (format: YYYY-MM-DD or YYYY-MM-DDTHH:mm:ssZ)
     * - page: Page number (default: 0)
     * - size: Page size (default: 20, max: 100)
     * - sortBy: Sort field (default: createdAt)
     * - sortDir: Sort direction (asc/desc, default: desc)
     */
    @GetMapping("/search")
    @PreAuthorize(SecurityConstants.ORDER_ADMIN_VIEW)
    public ResponseEntity<ApiResponse<Page<Order>>> searchOrders(
            @RequestParam(required = false) String userId,
            @RequestParam(required = false) String courseId,
            @RequestParam(required = false) OrderStatus status,
            @RequestParam(required = false) PaymentMethod paymentMethod,
            @RequestParam(required = false) String transactionId,
            @RequestParam(required = false) String phoneNumber,
            @RequestParam(required = false) String searchText,
            @RequestParam(required = false) String dateFrom,
            @RequestParam(required = false) String dateTo,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size,
            @RequestParam(defaultValue = "createdAt") String sortBy,
            @RequestParam(defaultValue = "desc") String sortDir) {

        log.info("Admin searching orders with filters - userId: {}, courseId: {}, status: {}, paymentMethod: {}, " +
                        "transactionId: {}, phoneNumber: {}, searchText: {}, dateFrom: {}, dateTo: {}",
                userId, courseId, status, paymentMethod, transactionId, phoneNumber, searchText, dateFrom, dateTo);

        // Validate pagination parameters
        if (page < 0) {
            return ResponseEntity.badRequest()
                    .body(ApiResponse.<Page<Order>>builder()
                            .success(false)
                            .message("Page number cannot be negative")
                            .build());
        }

        if (size <= 0 || size > 100) {
            return ResponseEntity.badRequest()
                    .body(ApiResponse.<Page<Order>>builder()
                            .success(false)
                            .message("Page size must be between 1 and 100")
                            .build());
        }

        // Create pageable with sorting
        org.springframework.data.domain.Sort.Direction direction =
                "asc".equalsIgnoreCase(sortDir) ?
                        org.springframework.data.domain.Sort.Direction.ASC :
                        org.springframework.data.domain.Sort.Direction.DESC;

        Pageable pageable = PageRequest.of(page, size,
                org.springframework.data.domain.Sort.by(direction, sortBy));

        try {
            Page<Order> orders = orderService.searchOrders(
                    userId, courseId, status, paymentMethod,
                    transactionId, phoneNumber, searchText,
                    dateFrom, dateTo, pageable
            );

            return ResponseEntity.ok(
                    ApiResponse.<Page<Order>>builder()
                            .success(true)
                            .message("Orders retrieved successfully")
                            .data(orders)
                            .build()
            );

        } catch (Exception e) {
            log.error("Error searching orders: {}", e.getMessage(), e);
            return ResponseEntity.badRequest()
                    .body(ApiResponse.<Page<Order>>builder()
                            .success(false)
                            .message("Failed to search orders: " + e.getMessage())
                            .build());
        }
    }

    /**
     * Quick search by transaction ID (for customer support)
     * GET /api/v1/orders/by-transaction/{transactionId}
     */
    @GetMapping("/by-transaction/{transactionId}")
    @PreAuthorize(SecurityConstants.ORDER_ADMIN_VIEW)
    public ResponseEntity<ApiResponse<Page<Order>>> getOrderByTransaction(
            @PathVariable String transactionId,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "5") int size) {

        log.info("Searching orders by transaction ID: {}", transactionId);

        Pageable pageable = PageRequest.of(page, size,
                org.springframework.data.domain.Sort.by(
                        org.springframework.data.domain.Sort.Direction.DESC, "createdAt"));

        try {
            Page<Order> orders = orderService.searchOrders(
                    null, null, null, null,
                    transactionId, null, null,
                    null, null, pageable
            );

            return ResponseEntity.ok(
                    ApiResponse.<Page<Order>>builder()
                            .success(true)
                            .message("Orders found for transaction ID")
                            .data(orders)
                            .build()
            );

        } catch (Exception e) {
            log.error("Error searching by transaction ID {}: {}", transactionId, e.getMessage(), e);
            return ResponseEntity.badRequest()
                    .body(ApiResponse.<Page<Order>>builder()
                            .success(false)
                            .message("Failed to search by transaction ID: " + e.getMessage())
                            .build());
        }
    }

    /**
     * Get orders by status (for admin dashboard widgets)
     * GET /api/v1/orders/status/{status}
     */
    @GetMapping("/status/{status}")
    @PreAuthorize(SecurityConstants.ORDER_ADMIN_VIEW)
    public ResponseEntity<ApiResponse<Page<Order>>> getOrdersByStatus(
            @PathVariable OrderStatus status,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size) {

        log.info("Admin retrieving orders with status: {}", status);

        Pageable pageable = PageRequest.of(page, size,
                org.springframework.data.domain.Sort.by(
                        org.springframework.data.domain.Sort.Direction.DESC, "createdAt"));

        try {
            Page<Order> orders = orderService.getOrdersByStatus(status, pageable);

            return ResponseEntity.ok(
                    ApiResponse.<Page<Order>>builder()
                            .success(true)
                            .message("Orders retrieved by status")
                            .data(orders)
                            .build()
            );

        } catch (Exception e) {
            log.error("Error retrieving orders by status {}: {}", status, e.getMessage(), e);
            return ResponseEntity.badRequest()
                    .body(ApiResponse.<Page<Order>>builder()
                            .success(false)
                            .message("Failed to retrieve orders by status: " + e.getMessage())
                            .build());
        }
    }

    /**
     * Get pending verification orders (admin work queue)
     * GET /api/v1/orders/pending-verification
     */
    @GetMapping("/pending-verification")
    @PreAuthorize(SecurityConstants.ORDER_ADMIN_VIEW)
    public ResponseEntity<ApiResponse<Page<Order>>> getPendingVerificationOrders(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size) {

        log.info("Admin retrieving pending verification orders");

        Pageable pageable = PageRequest.of(page, size,
                org.springframework.data.domain.Sort.by(
                        org.springframework.data.domain.Sort.Direction.ASC, "lastPaymentAttemptAt"));

        try {
            Page<Order> orders = orderService.getPendingVerificationOrders(pageable);

            return ResponseEntity.ok(
                    ApiResponse.<Page<Order>>builder()
                            .success(true)
                            .message("Pending verification orders retrieved")
                            .data(orders)
                            .build()
            );

        } catch (Exception e) {
            log.error("Error retrieving pending verification orders: {}", e.getMessage(), e);
            return ResponseEntity.badRequest()
                    .body(ApiResponse.<Page<Order>>builder()
                            .success(false)
                            .message("Failed to retrieve pending verification orders: " + e.getMessage())
                            .build());
        }
    }

    /**
     * Get order by ID (admin access)
     * GET /api/v1/orders/admin/{orderId}
     */
    @GetMapping("/admin/{orderId}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<Order>> getOrderById(
            @PathVariable String orderId) {

        log.debug("Admin retrieving order by ID: {}", orderId);

        try {
            Order order = orderService.getOrderById(orderId);
            
            return ResponseEntity.ok(
                    ApiResponse.success("Order retrieved successfully", order));

        } catch (ValidationException e) {
            log.warn("Validation error retrieving order {}: {}", orderId, e.getMessage());
            return ResponseEntity.badRequest()
                    .body(ApiResponse.error("Order retrieval failed: " + e.getMessage(), "VALIDATION_ERROR"));
        } catch (Exception e) {
            log.error("Error retrieving order {}: {}", orderId, e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(ApiResponse.error("Order not found", "ORDER_NOT_FOUND"));
        }
    }

    // ==================== ANALYTICS AND STATISTICS ====================

    /**
     * Get order statistics for admin dashboard
     * GET /api/v1/orders/statistics
     */
    @GetMapping("/statistics")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<OrderService.OrderStatistics>> getOrderStatistics() {

        log.info("Admin retrieving order statistics");

        try {
            OrderService.OrderStatistics statistics = orderService.getOrderStatistics();
            
            return ResponseEntity.ok(
                    ApiResponse.success("Order statistics retrieved successfully", statistics));

        } catch (Exception e) {
            log.error("Error retrieving order statistics: {}", e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponse.error("Failed to retrieve order statistics", "STATISTICS_ERROR"));
        }
    }

    /**
     * Get daily order summary for reporting
     * GET /api/v1/orders/daily-summary
     */
    @GetMapping("/daily-summary")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<List<OrderService.DailyOrderSummary>>> getDailyOrderSummary(
            @RequestParam(defaultValue = "30") int days) {

        log.info("Admin retrieving daily order summary for {} days", days);

        // Validate days parameter
        if (days <= 0 || days > 365) {
            return ResponseEntity.badRequest()
                    .body(ApiResponse.<List<OrderService.DailyOrderSummary>>builder()
                            .success(false)
                            .message("Days parameter must be between 1 and 365")
                            .build());
        }

        try {
            List<OrderService.DailyOrderSummary> dailySummary = orderService.getDailyOrderSummary(days);
            
            return ResponseEntity.ok(
                    ApiResponse.success("Daily order summary retrieved successfully", dailySummary));

        } catch (Exception e) {
            log.error("Error retrieving daily order summary: {}", e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponse.error("Failed to retrieve daily order summary", "DAILY_SUMMARY_ERROR"));
        }
    }

    /**
     * Get course revenue
     * GET /api/v1/orders/course/{courseId}/revenue
     */
    @GetMapping("/course/{courseId}/revenue")
    @PreAuthorize(SecurityConstants.ORDER_ADMIN_VIEW)
    public ResponseEntity<ApiResponse<BigDecimal>> getCourseRevenue(
            @PathVariable String courseId) {

        log.info("Admin retrieving revenue for course: {}", courseId);

        try {
            BigDecimal revenue = orderService.getCourseRevenue(courseId);
            
            return ResponseEntity.ok(
                    ApiResponse.success("Course revenue retrieved successfully", revenue));

        } catch (ValidationException e) {
            log.warn("Validation error retrieving course revenue for {}: {}", courseId, e.getMessage());
            return ResponseEntity.badRequest()
                    .body(ApiResponse.error("Course revenue retrieval failed: " + e.getMessage(), "VALIDATION_ERROR"));
        } catch (Exception e) {
            log.error("Error retrieving course revenue for {}: {}", courseId, e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponse.error("Failed to retrieve course revenue", "REVENUE_ERROR"));
        }
    }

    /**
     * Get user's purchased course IDs
     * GET /api/v1/orders/user/{userId}/purchased-courses
     */
    @GetMapping("/user/{userId}/purchased-courses")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<List<String>>> getUserPurchasedCourses(
            @PathVariable String userId) {

        log.info("Admin retrieving purchased courses for user: {}", userId);

        try {
            List<String> courseIds = orderService.getUserPurchasedCourseIds(userId);
            
            return ResponseEntity.ok(
                    ApiResponse.success("User purchased courses retrieved successfully", courseIds));

        } catch (ValidationException e) {
            log.warn("Validation error retrieving purchased courses for user {}: {}", userId, e.getMessage());
            return ResponseEntity.badRequest()
                    .body(ApiResponse.error("User purchased courses retrieval failed: " + e.getMessage(), "VALIDATION_ERROR"));
        } catch (Exception e) {
            log.error("Error retrieving purchased courses for user {}: {}", userId, e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponse.error("Failed to retrieve user purchased courses", "PURCHASED_COURSES_ERROR"));
        }
    }

    // ==================== MAINTENANCE OPERATIONS ====================

    /**
     * Process expired orders (admin maintenance)
     * POST /api/v1/orders/process-expired
     */
    @PostMapping("/process-expired")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<Integer>> processExpiredOrders() {

        log.info("Admin initiated expired orders processing");

        try {
            int processedCount = orderService.processExpiredOrders();
            
            log.info("Processed {} expired orders", processedCount);

            return ResponseEntity.ok(
                    ApiResponse.success("Expired orders processed successfully", processedCount));

        } catch (Exception e) {
            log.error("Error processing expired orders: {}", e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponse.error("Failed to process expired orders", "EXPIRED_ORDERS_ERROR"));
        }
    }

    /**
     * Revoke course access (for refunds/violations)
     * PUT /api/v1/orders/{orderId}/revoke
     */
    @PutMapping("/{orderId}/revoke")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<Order>> revokeAccess(
            @PathVariable String orderId,
            @Valid @RequestBody RevokeAccessRequest request,
            Authentication authentication) {

        UserPrincipal principal = (UserPrincipal) authentication.getPrincipal();
        log.info("Admin {} revoking access for order: {}", principal.getId(), orderId);

        try {
            Order revokedOrder = orderService.revokeAccess(orderId, principal.getId(), request.getRevocationReason());
            
            return ResponseEntity.ok(
                    ApiResponse.success("Access revoked successfully", revokedOrder));

        } catch (ValidationException e) {
            log.warn("Validation error revoking access for order {}: {}", orderId, e.getMessage());
            return ResponseEntity.badRequest()
                    .body(ApiResponse.error("Access revocation failed: " + e.getMessage(), "VALIDATION_ERROR"));
        } catch (Exception e) {
            log.error("Error revoking access for order {}: {}", orderId, e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponse.error("Failed to revoke access", "REVOKE_ACCESS_ERROR"));
        }
    }

    /**
     * Get all orders with pagination (admin view)
     * GET /api/v1/orders/admin
     */
    @GetMapping("/admin")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<Page<Order>>> getAllOrders(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size,
            @RequestParam(defaultValue = "createdAt") String sortBy,
            @RequestParam(defaultValue = "desc") String sortDir) {

        log.debug("Admin retrieving all orders - page: {}, size: {}", page, size);

        try {
            Sort.Direction direction = sortDir.equalsIgnoreCase("desc") 
                    ? Sort.Direction.DESC 
                    : Sort.Direction.ASC;
            
            Pageable pageable = PageRequest.of(page, size, Sort.by(direction, sortBy));
            Page<Order> orders = orderService.getAllOrders(pageable);
            
            return ResponseEntity.ok(
                    ApiResponse.success("All orders retrieved successfully", orders));

        } catch (Exception e) {
            log.error("Error retrieving all orders: {}", e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponse.error("Failed to retrieve orders", "GET_ALL_ORDERS_ERROR"));
        }
    }

    /**
     * Check if user has active purchase for course
     * GET /api/v1/orders/check-access/{userId}/{courseId}
     */
    @GetMapping("/check-access/{userId}/{courseId}")
    @PreAuthorize(SecurityConstants.ADMIN_OR_OWNER)
    public ResponseEntity<ApiResponse<Boolean>> checkUserCourseAccess(
            @PathVariable String userId,
            @PathVariable String courseId) {

        log.debug("Checking course access for user: {} and course: {}", userId, courseId);

        try {
            boolean hasAccess = orderService.hasActivePurchase(userId, courseId);
            
            return ResponseEntity.ok(
                    ApiResponse.success("Course access check completed", hasAccess));

        } catch (Exception e) {
            log.error("Error checking course access for user {} and course {}: {}", userId, courseId, e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponse.error("Failed to check course access", "CHECK_ACCESS_ERROR"));
        }
    }
}
