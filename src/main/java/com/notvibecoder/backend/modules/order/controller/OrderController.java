package com.notvibecoder.backend.modules.order.controller;

import com.notvibecoder.backend.core.dto.ApiResponse;
import com.notvibecoder.backend.modules.order.entity.Order;
import com.notvibecoder.backend.modules.order.entity.OrderStatus;
import com.notvibecoder.backend.modules.order.entity.PaymentMethod;
import com.notvibecoder.backend.modules.order.service.OrderService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.security.Principal;

@RestController
@RequestMapping("/api/v1/orders")
@RequiredArgsConstructor
@Slf4j
public class OrderController {

    private final OrderService orderService;

    @GetMapping("/search")
    @PreAuthorize("hasRole('ADMIN')")
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
     * Get user's own orders with search capability
     * GET /api/v1/orders/my-orders
     */
    @GetMapping("/my-orders")
    @PreAuthorize("hasRole('USER')")
    public ResponseEntity<ApiResponse<Page<Order>>> getMyOrders(
            @RequestParam(required = false) OrderStatus status,
            @RequestParam(required = false) String courseId,
            @RequestParam(required = false) String searchText,
            @RequestParam(required = false) String dateFrom,
            @RequestParam(required = false) String dateTo,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size,
            Principal principal) {

        String userId = principal.getName(); // Assuming principal name is user ID

        log.info("User {} searching their orders with filters - status: {}, courseId: {}, searchText: {}, dateFrom: {}, dateTo: {}",
                userId, status, courseId, searchText, dateFrom, dateTo);

        // Validate pagination parameters
        if (page < 0 || size <= 0 || size > 50) {
            return ResponseEntity.badRequest()
                    .body(ApiResponse.<Page<Order>>builder()
                            .success(false)
                            .message("Invalid pagination parameters")
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

    /**
     * Quick search by transaction ID (for customer support)
     * GET /api/v1/orders/by-transaction/{transactionId}
     */
    @GetMapping("/by-transaction/{transactionId}")
    @PreAuthorize("hasRole('ADMIN') or hasRole('SUPPORT')")
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
    @PreAuthorize("hasRole('ADMIN')")
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
    @PreAuthorize("hasRole('ADMIN')")
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
}
