package com.notvibecoder.backend.modules.order.repository;

import java.util.List;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.data.mongodb.repository.Query;
import org.springframework.stereotype.Repository;

import com.notvibecoder.backend.modules.order.entity.Order;
import com.notvibecoder.backend.modules.order.entity.OrderStatus;
import com.notvibecoder.backend.modules.order.entity.PaymentMethod;

@Repository
public interface OrderRepository extends MongoRepository<Order, String> {

    /**
     * Check if user has an order for a course with specific status
     */
    @Query("{ 'userId': ?0, 'courseId': ?1, 'status': ?2 }")
    boolean existsByUserIdAndCourseIdAndStatus(String userId, String courseId, OrderStatus status);

    /**
     * Check if transaction ID already exists for orders with specific status
     */
    @Query("{ 'transactionId': ?0, 'status': ?1 }")
    boolean existsByTransactionIdAndStatus(String transactionId, OrderStatus status);

    /**
     * Find all orders for a specific user, ordered by creation date (newest first)
     */
    @Query("{ 'userId': ?0 }")
    Page<Order> findByUserIdOrderByCreatedAtDesc(String userId, Pageable pageable);

    /**
     * Find all orders, ordered by creation date (newest first)
     */
    Page<Order> findAllByOrderByCreatedAtDesc(Pageable pageable);

    /**
     * Find all verified orders for a user to get their purchased course IDs
     */
    List<Order> findByUserIdAndStatus(String userId, OrderStatus status);

    /**
     * Find orders by status with pagination, ordered by creation date
     */
    Page<Order> findByStatusOrderByCreatedAtDesc(OrderStatus status, Pageable pageable);

    /**
     * Find all verified orders for a specific course to calculate revenue
     */
    @Query("{ 'courseId': ?0, 'status': 'VERIFIED' }")
    List<Order> findByCourseIdAndStatusVerified(String courseId);

    /**
     * Count orders by status for statistics
     */
    long countByStatus(OrderStatus status);

    /**
     * Get total revenue (sum of totalAmount for VERIFIED orders)
     */
    @Query(value = "{ 'status': 'VERIFIED' }", fields = "{ 'totalAmount': 1 }")
    List<Order> findVerifiedOrdersForRevenue();

    /**
     * Find orders created between dates for daily summary
     */
    @Query("{ 'createdAt': { $gte: ?0, $lt: ?1 } }")
    List<Order> findOrdersBetweenDates(java.time.Instant startDate, java.time.Instant endDate);

    /**
     * Find expired pending orders (older than specified date)
     */
    @Query("{ 'status': 'PENDING', 'createdAt': { $lt: ?0 } }")
    List<Order> findExpiredPendingOrders(java.time.Instant expiryDate);

    /**
     * Generalized search query using MongoDB's flexible querying
     * This uses SpEL (Spring Expression Language) to build dynamic queries
     * 
     * The query dynamically includes only non-null parameters:
     * - If parameter is null, it contributes an empty object {} to the $and array
     * - If parameter is not null, it creates the appropriate filter condition
     * 
     * Example usage:
     * - searchOrders(null, "course123", null, null, null, null, null, null, null, pageable)
     *   Results in: { $and: [ {}, { 'courseId': 'course123' }, {}, {}, {}, {}, {}, {}, {} ] }
     * 
     * - searchOrders("user123", null, "VERIFIED", null, null, null, "John", startDate, endDate, pageable)
     *   Results in: { $and: [ 
     *     { 'userId': 'user123' }, 
     *     {}, 
     *     { 'status': 'VERIFIED' }, 
     *     {}, {}, {}, 
     *     { $or: [{'userName': {$regex: 'John', $options: 'i'}}, ...] },
     *     { 'createdAt': { $gte: startDate } },
     *     { 'createdAt': { $lte: endDate } }
     *   ] }
     */
    @Query("{ $and: [ " +
           "?#{[0] == null ? {} : { 'userId': [0] }}, " +
           "?#{[1] == null ? {} : { 'courseId': [1] }}, " +
           "?#{[2] == null ? {} : { 'status': [2] }}, " +
           "?#{[3] == null ? {} : { 'paymentMethod': [3] }}, " +
           "?#{[4] == null ? {} : { 'transactionId': { $regex: [4], $options: 'i' } }}, " +
           "?#{[5] == null ? {} : { 'phoneNumber': { $regex: [5], $options: 'i' } }}, " +
           "?#{[6] == null ? {} : { $or: [ " +
           "  { 'userName': { $regex: [6], $options: 'i' } }, " +
           "  { 'userEmail': { $regex: [6], $options: 'i' } }, " +
           "  { 'courseTitle': { $regex: [6], $options: 'i' } }, " +
           "  { 'courseInstructor': { $regex: [6], $options: 'i' } } " +
           "] }}, " +
           "?#{[7] == null ? {} : { 'createdAt': { $gte: [7] } }}, " +
           "?#{[8] == null ? {} : { 'createdAt': { $lte: [8] } }} " +
           "] }")
    Page<Order> searchOrders(String userId, String courseId, OrderStatus status, 
                           PaymentMethod paymentMethod, String transactionId, 
                           String phoneNumber, String searchText, 
                           java.time.Instant dateFrom, java.time.Instant dateTo, 
                           Pageable pageable);

}
