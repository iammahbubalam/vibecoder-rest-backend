package com.notvibecoder.backend.modules.order.service;

import com.notvibecoder.backend.modules.order.entity.Order;
import com.notvibecoder.backend.modules.order.entity.OrderStatus;
import com.notvibecoder.backend.modules.order.entity.PaymentMethod;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

import java.math.BigDecimal;
import java.util.List;

/**
 * Order Service Interface - Complete order lifecycle management
 * <p>
 * Business Flow:
 * 1. User creates order for a course
 * 2. User submits payment details
 * 3. Admin verifies payment
 * 4. Course access is granted/denied
 */
public interface OrderService {

    /**
     * Create a new order for a course
     *
     * @param userId   User placing the order
     * @param courseId Course ID
     * @return Created order
     */
    Order createOrder(String userId, String courseId);

    /**
     * Submit payment information for pending order
     *
     * @param orderId       Order ID
     * @param paymentMethod Payment method used
     * @param transactionId Transaction ID from payment provider
     * @param phoneNumber   User's phone number
     * @param paymentNote   Optional payment reference note
     * @return Updated order with payment info
     */
    Order submitPayment(String orderId, PaymentMethod paymentMethod, String transactionId,
                        String phoneNumber, String paymentNote);

    /**
     * Cancel an order (only if in PENDING_PAYMENT status)
     *
     * @param orderId Order ID
     * @param userId  User ID (for authorization)
     * @return Cancelled order
     */
    Order cancelOrder(String orderId, String userId);


    /**
     * Approve payment and grant course access
     *
     * @param orderId   Order ID
     * @param adminId   Admin performing the action
     * @param adminNote Optional admin note
     * @return Approved order
     */
    Order approvePayment(String orderId, String adminId, String adminNote);

    /**
     * Reject payment with reason
     *
     * @param orderId         Order ID
     * @param adminId         Admin performing the action
     * @param rejectionReason Reason for rejection
     * @return Rejected order
     */
    Order rejectPayment(String orderId, String adminId, String rejectionReason);

    /**
     * Revoke course access (for refunds/violations)
     *
     * @param orderId          Order ID
     * @param adminId          Admin performing the action
     * @param revocationReason Reason for revocation
     * @return Order with revoked access
     */
    Order revokeAccess(String orderId, String adminId, String revocationReason);


    /**
     * Get order by ID (with authorization check)
     *
     * @param orderId Order ID
     * @param userId  User ID (for authorization)
     * @return Order details
     */
    Order getOrder(String orderId, String userId);

    /**
     * Get order by ID (admin access - no authorization check)
     *
     * @param orderId Order ID
     * @return Order details
     */
    Order getOrderById(String orderId);

    /**
     * Check if a user owns a specific order
     *
     * @param userId  User ID
     * @param orderId Order ID
     * @return true if user owns the order, false otherwise
     */
    boolean isOwner(String userId, String orderId);

    /**
     * Get user's order history
     *
     * @param userId   User ID
     * @param pageable Pagination info
     * @return Page of user orders
     */
    Page<Order> getUserOrders(String userId, Pageable pageable);

    /**
     * Get all orders (admin view)
     *
     * @param pageable Pagination info
     * @return Page of all orders
     */
    Page<Order> getAllOrders(Pageable pageable);

    /**
     * Check if user has active purchase for course
     *
     * @param userId   User ID
     * @param courseId Course ID
     * @return true if user has access to course
     */
    boolean hasActivePurchase(String userId, String courseId);

    /**
     * Get user's purchased course IDs
     *
     * @param userId User ID
     * @return List of course IDs user has access to
     */
    List<String> getUserPurchasedCourseIds(String userId);


    /**
     * Get orders by status for admin dashboard
     *
     * @param status   Order status filter
     * @param pageable Pagination info
     * @return Page of orders
     */
    Page<Order> getOrdersByStatus(OrderStatus status, Pageable pageable);

    /**
     * Get pending verification orders (admin work queue)
     *
     * @param pageable Pagination info
     * @return Page of orders pending verification
     */
    Page<Order> getPendingVerificationOrders(Pageable pageable);

    /**
     * Search orders by various criteria (all parameters are optional - pass null to ignore)
     *
     * @param userId        Optional user ID filter (null to ignore)
     * @param courseId      Optional course ID filter (null to ignore)
     * @param status        Optional status filter (null to ignore)
     * @param paymentMethod Optional payment method filter (null to ignore)
     * @param transactionId Optional transaction ID filter (null to ignore)
     * @param phoneNumber   Optional phone number filter (null to ignore)
     * @param searchText    Optional text search across user name, email, course title (null to ignore)
     * @param dateFrom      Optional start date filter in format "2025-01-01" (null to ignore)
     * @param dateTo        Optional end date filter in format "2025-12-31" (null to ignore)
     * @param pageable      Pagination info
     * @return Page of matching orders
     */
    Page<Order> searchOrders(String userId, String courseId, OrderStatus status,
                             PaymentMethod paymentMethod, String transactionId,
                             String phoneNumber, String searchText,
                             String dateFrom, String dateTo, Pageable pageable);


    /**
     * Get total revenue for a course
     *
     * @param courseId Course ID
     * @return Total revenue amount
     */
    BigDecimal getCourseRevenue(String courseId);

    /**
     * Get order statistics for admin dashboard
     *
     * @return Order counts by status
     */
    OrderStatistics getOrderStatistics();

    /**
     * Get daily order summary for reporting
     *
     * @param days Number of days to look back
     * @return List of daily summaries
     */
    List<DailyOrderSummary> getDailyOrderSummary(int days);


    /**
     * Process expired orders (cleanup job)
     *
     * @return Number of orders expired
     */
    int processExpiredOrders();


    /**
     * Order statistics for admin dashboard
     */
    record OrderStatistics(
            long totalOrders,
            long pendingPayment,
            long pendingVerification,
            long completed,
            long rejected,
            long cancelled,
            BigDecimal totalRevenue
    ) {
    }

    /**
     * Daily order summary for reporting
     */
    record DailyOrderSummary(
            String date,
            long orderCount,
            BigDecimal revenue,
            long newCustomers
    ) {
    }

}
