package com.notvibecoder.backend.modules.order.service;

import com.notvibecoder.backend.core.exception.ValidationException;
import com.notvibecoder.backend.modules.courses.entity.Course;
import com.notvibecoder.backend.modules.courses.entity.CourseStatus;
import com.notvibecoder.backend.modules.courses.service.CourseService;
import com.notvibecoder.backend.modules.order.entity.Order;
import com.notvibecoder.backend.modules.order.entity.OrderStatus;
import com.notvibecoder.backend.modules.order.entity.PaymentMethod;
import com.notvibecoder.backend.modules.order.repository.OrderRepository;
import com.notvibecoder.backend.modules.user.entity.User;
import com.notvibecoder.backend.modules.user.service.UserServiceImpl;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.math.BigDecimal;
import java.util.List;

@Service
@RequiredArgsConstructor
@Slf4j
public class OrderServiceImpl implements OrderService {

    private final OrderRepository orderRepository;
    private final UserServiceImpl userServiceImpl;
    private final CourseService courseService;

    @Override
    @Transactional
    public Order createOrder(String userId, String courseId) {
        // Input validation
        if (userId == null || userId.trim().isEmpty()) {
            throw new ValidationException("User ID cannot be null or empty", "USER_ID_REQUIRED");
        }
        if (courseId == null || courseId.trim().isEmpty()) {
            throw new ValidationException("Course ID cannot be null or empty", "COURSE_ID_REQUIRED");
        }

        log.info("Creating order for user: {} and course: {}", userId, courseId);

        try {
            // Validate user exists and is active
            User user = userServiceImpl.findById(userId);
            if (!user.getEnabled()) {
                throw new ValidationException("User account is disabled");
            }

            // Validate course exists and is published
            Course course = courseService.getCourse(courseId);
            if (course.getStatus() != CourseStatus.PUBLISHED) {
                throw new ValidationException("Course is not available for purchase");
            }

            // Check if user already has an active order or purchase for this course
            boolean hasExistingPurchase = hasActivePurchase(userId, courseId);
            if (hasExistingPurchase) {
                throw new ValidationException("User already has access to this course");
            }

            // Calculate pricing
            BigDecimal coursePrice = course.getPrice();
            BigDecimal totalAmount = calculateDiscountedPrice(course.getDiscountPrice(), courseId, coursePrice);


            // Ensure total amount is not negative
            if (totalAmount.compareTo(BigDecimal.ZERO) < 0) {
                totalAmount = BigDecimal.ZERO;
            }

            // Build order entity
            Order order = Order.builder()
                    .userId(userId)
                    .courseId(courseId)
                    .status(OrderStatus.PENDING)
                    .coursePrice(coursePrice)
                    .discountAmount(course.getDiscountPrice())
                    .totalAmount(totalAmount)
                    // Course snapshot for historical reference
                    .courseTitle(course.getTitle())
                    .courseInstructor(course.getInstructorName())
                    .courseThumbnailUrl(course.getThumbnailUrl())
                    // User snapshot for admin reference
                    .userName(user.getName())
                    .userEmail(user.getEmail())
                    // Metadata
                    .currency("BDT")
                    .build();

            // Save order
            Order savedOrder = orderRepository.save(order);

            log.info("Order created successfully with ID: {} for user: {} and course: {}, total amount: {}",
                    savedOrder.getId(), userId, courseId, totalAmount);

            return savedOrder;

        } catch (DataIntegrityViolationException e) {
            // Handle unique constraint violation (user already has order for this course)
            log.warn("Duplicate order attempt for user: {} and course: {}", userId, courseId);
            throw new ValidationException("An order for this course already exists");
        } catch (ValidationException e) {
            // Re-throw validation exceptions
            throw e;
        } catch (Exception e) {
            log.error("Unexpected error creating order for user: {} and course: {}: {}",
                    userId, courseId, e.getMessage(), e);
            throw new ValidationException("Failed to create order: " + e.getMessage());
        }
    }


    @Override
    @Transactional
    public Order submitPayment(String orderId, PaymentMethod paymentMethod, String transactionId, String phoneNumber,
                               String paymentNote) {
        // Input validation
        if (orderId == null || orderId.trim().isEmpty()) {
            throw new ValidationException("Order ID cannot be null or empty");
        }
        if (paymentMethod == null) {
            throw new ValidationException("Payment method is required");
        }
        if (transactionId == null || transactionId.trim().isEmpty()) {
            throw new ValidationException("Transaction ID is required");
        }
        if (phoneNumber == null || phoneNumber.trim().isEmpty()) {
            throw new ValidationException("Phone number is required");
        }

        log.info("Submitting payment for order: {} with transaction: {}", orderId, transactionId);

        try {
            // Find and validate order
            Order order = orderRepository.findById(orderId)
                    .orElseThrow(() -> new ValidationException("Order not found with ID: " + orderId));

            // Check if order is in correct status for payment submission
            if (order.getStatus() != OrderStatus.PENDING) {
                throw new ValidationException("Order is not in pending status. Current status: " + order.getStatus());
            }

            // Check for duplicate transaction ID
            if (orderRepository.existsByTransactionIdAndStatus(transactionId, OrderStatus.PENDING)) {
                throw new ValidationException("Transaction ID already exists for another pending order");
            }

            // Update order with payment information
            order.setPaymentMethod(paymentMethod);
            order.setTransactionId(transactionId);
            order.setPhoneNumber(phoneNumber);
            order.setPaymentReferenceNote(paymentNote);
            order.setStatus(OrderStatus.SUBMITTED);
            order.setLastPaymentAttemptAt(java.time.Instant.now());

            // Note: Status remains PENDING - admin will verify and change to VERIFIED

            // Save updated order
            Order updatedOrder = orderRepository.save(order);

            log.info("Payment submitted successfully for order: {} with transaction: {}",
                    orderId, transactionId);

            return updatedOrder;

        } catch (DataIntegrityViolationException e) {
            // Handle unique constraint violations (e.g., duplicate transaction ID)
            log.warn("Data integrity violation when submitting payment for order: {}", orderId);
            throw new ValidationException("Transaction ID already exists or duplicate payment submission");
        } catch (ValidationException e) {
            // Re-throw validation exceptions
            throw e;
        } catch (Exception e) {
            log.error("Unexpected error submitting payment for order: {}: {}",
                    orderId, e.getMessage(), e);
            throw new ValidationException("Failed to submit payment: " + e.getMessage());
        }
    }

    @Override
    @Transactional
    public Order cancelOrder(String orderId, String userId) {
        // Input validation
        if (orderId == null || orderId.trim().isEmpty()) {
            throw new ValidationException("Order ID cannot be null or empty");
        }
        if (userId == null || userId.trim().isEmpty()) {
            throw new ValidationException("User ID cannot be null or empty");
        }

        log.info("Cancelling order: {} for user: {}", orderId, userId);

        try {
            // Find and validate order
            Order order = orderRepository.findById(orderId)
                    .orElseThrow(() -> new ValidationException("Order not found with ID: " + orderId));

            // Authorization check - ensure user owns this order
            if (!order.getUserId().equals(userId)) {
                log.warn("Unauthorized cancel attempt - Order: {} does not belong to user: {}", orderId, userId);
                throw new ValidationException("You are not authorized to cancel this order");
            }

            // Business rule - only allow cancellation for PENDING orders
            if (order.getStatus() != OrderStatus.PENDING) {
                throw new ValidationException("Order cannot be cancelled. Current status: " + order.getStatus());
            }

            // Update order status to REJECTED (reusing existing enum value for cancelled orders)
            order.setStatus(OrderStatus.REJECTED);
            order.setRejectionReason("Cancelled by user");

            // Save updated order
            Order cancelledOrder = orderRepository.save(order);

            log.info("Order cancelled successfully: {} by user: {}", orderId, userId);
            return cancelledOrder;

        } catch (ValidationException e) {
            throw e;
        } catch (Exception e) {
            log.error("Unexpected error cancelling order: {} for user: {}: {}",
                    orderId, userId, e.getMessage(), e);
            throw new ValidationException("Failed to cancel order: " + e.getMessage());
        }
    }

    @Override
    @Transactional
    public Order approvePayment(String orderId, String adminId, String adminNote) {
        // Input validation
        if (orderId == null || orderId.trim().isEmpty()) {
            throw new ValidationException("Order ID cannot be null or empty");
        }
        if (adminId == null || adminId.trim().isEmpty()) {
            throw new ValidationException("Admin ID cannot be null or empty");
        }

        log.info("Approving payment for order: {} by admin: {}", orderId, adminId);

        try {
            // Find and validate order
            Order order = orderRepository.findById(orderId)
                    .orElseThrow(() -> new ValidationException("Order not found with ID: " + orderId));

            // Validate admin exists and has appropriate permissions
            User admin = userServiceImpl.findById(adminId);
            if (!admin.getEnabled()) {
                throw new ValidationException("Admin account is disabled");
            }


            // Business rule - only allow approval for SUBMITTED orders
            if (order.getStatus() != OrderStatus.SUBMITTED) {
                throw new ValidationException("Order cannot be approved. Current status: " + order.getStatus() +
                        ". Only SUBMITTED orders can be approved.");
            }

            // Validate payment information exists
            if (order.getTransactionId() == null || order.getTransactionId().trim().isEmpty()) {
                throw new ValidationException("Order does not have payment information to approve");
            }

            // Update order status and admin information
            order.setStatus(OrderStatus.VERIFIED);
            order.setVerifiedBy(adminId);
            order.setVerifiedAt(java.time.Instant.now());
            order.setAdminNote(adminNote);

            // Save updated order
            Order approvedOrder = orderRepository.save(order);

            // Grant course access to user by adding courseId to user's purchased courses
            try {
                userServiceImpl.addPurchasedCourse(order.getUserId(), order.getCourseId());
                log.info("Course access granted: Added course {} to user {}", order.getCourseId(), order.getUserId());
            } catch (Exception e) {
                log.error("Failed to grant course access for order: {} - course: {} to user: {}. Error: {}",
                        orderId, order.getCourseId(), order.getUserId(), e.getMessage());
            }

            log.info("Payment approved successfully for order: {} by admin: {}. User {} now has access to course: {}",
                    orderId, adminId, order.getUserId(), order.getCourseId());

            // TODO: Optionally trigger course access grant notification or other side effects

            return approvedOrder;

        } catch (ValidationException e) {
            throw e;
        } catch (Exception e) {
            log.error("Unexpected error approving payment for order: {} by admin: {}: {}",
                    orderId, adminId, e.getMessage(), e);
            throw new ValidationException("Failed to approve payment: " + e.getMessage());
        }
    }

    @Override
    @Transactional
    public Order rejectPayment(String orderId, String adminId, String rejectionReason) {
        // Input validation
        if (orderId == null || orderId.trim().isEmpty()) {
            throw new ValidationException("Order ID cannot be null or empty");
        }
        if (adminId == null || adminId.trim().isEmpty()) {
            throw new ValidationException("Admin ID cannot be null or empty");
        }
        if (rejectionReason == null || rejectionReason.trim().isEmpty()) {
            throw new ValidationException("Rejection reason is required");
        }

        log.info("Rejecting payment for order: {} by admin: {}", orderId, adminId);

        try {
            // Find and validate order
            Order order = orderRepository.findById(orderId)
                    .orElseThrow(() -> new ValidationException("Order not found with ID: " + orderId));

            // Validate admin exists and has appropriate permissions
            User admin = userServiceImpl.findById(adminId);
            if (!admin.getEnabled()) {
                throw new ValidationException("Admin account is disabled");
            }
            // Additional admin role validation could be added here based on your User entity structure

            // Business rule - only allow rejection for SUBMITTED orders
            if (order.getStatus() != OrderStatus.SUBMITTED) {
                throw new ValidationException("Order cannot be rejected. Current status: " + order.getStatus() +
                        ". Only SUBMITTED orders can be rejected.");
            }

            // Validate payment information exists
            if (order.getTransactionId() == null || order.getTransactionId().trim().isEmpty()) {
                throw new ValidationException("Order does not have payment information to reject");
            }

            // Update order status and admin information
            order.setStatus(OrderStatus.REJECTED);
            order.setVerifiedBy(adminId);
            order.setVerifiedAt(java.time.Instant.now());
            order.setRejectionReason(rejectionReason);
            order.setAdminNote("Payment rejected: " + rejectionReason);

            // Save updated order
            Order rejectedOrder = orderRepository.save(order);

            log.info("Payment rejected successfully for order: {} by admin: {}. Reason: {}",
                    orderId, adminId, rejectionReason);

            // TODO: Optionally trigger rejection notification to user

            return rejectedOrder;

        } catch (ValidationException e) {
            // Re-throw validation exceptions
            throw e;
        } catch (Exception e) {
            log.error("Unexpected error rejecting payment for order: {} by admin: {}: {}",
                    orderId, adminId, e.getMessage(), e);
            throw new ValidationException("Failed to reject payment: " + e.getMessage());
        }
    }

    @Override
    @Transactional
    public Order revokeAccess(String orderId, String adminId, String revocationReason) {
        // Input validation
        if (orderId == null || orderId.trim().isEmpty()) {
            throw new ValidationException("Order ID cannot be null or empty");
        }
        if (adminId == null || adminId.trim().isEmpty()) {
            throw new ValidationException("Admin ID cannot be null or empty");
        }
        if (revocationReason == null || revocationReason.trim().isEmpty()) {
            throw new ValidationException("Revocation reason is required");
        }

        log.info("Revoking course access for order: {} by admin: {}", orderId, adminId);

        try {
            // Find and validate order
            Order order = orderRepository.findById(orderId)
                    .orElseThrow(() -> new ValidationException("Order not found with ID: " + orderId));

            // Validate admin exists and has appropriate permissions
            User admin = userServiceImpl.findById(adminId);
            if (!admin.getEnabled()) {
                throw new ValidationException("Admin account is disabled");
            }
            // Additional admin role validation could be added here based on your User entity structure

            // Business rule - only allow revocation for VERIFIED orders (active course access)
            if (order.getStatus() != OrderStatus.VERIFIED) {
                throw new ValidationException("Order cannot be revoked. Current status: " + order.getStatus() +
                        ". Only VERIFIED orders can be revoked.");
            }

            // Remove course access from user
            try {
                userServiceImpl.removePurchasedCourse(order.getUserId(), order.getCourseId());
                log.info("Course access revoked: Removed course {} from user {}", order.getCourseId(), order.getUserId());
            } catch (Exception e) {
                log.error("Failed to revoke course access for order: {} - course: {} from user: {}. Error: {}",
                        orderId, order.getCourseId(), order.getUserId(), e.getMessage());
                // Continue with order update even if user update fails for audit trail
            }

            // Update order status and admin information
            order.setStatus(OrderStatus.REJECTED);
            order.setVerifiedBy(adminId);
            order.setVerifiedAt(java.time.Instant.now());
            order.setRejectionReason(revocationReason);
            order.setAdminNote("Access revoked: " + revocationReason);

            // Save updated order
            Order revokedOrder = orderRepository.save(order);

            log.info("Course access revoked successfully for order: {} by admin: {}. Reason: {}",
                    orderId, adminId, revocationReason);

            // TODO: Optionally trigger revocation notification to user

            return revokedOrder;

        } catch (ValidationException e) {
            // Re-throw validation exceptions
            throw e;
        } catch (Exception e) {
            log.error("Unexpected error revoking access for order: {} by admin: {}: {}",
                    orderId, adminId, e.getMessage(), e);
            throw new ValidationException("Failed to revoke access: " + e.getMessage());
        }
    }

    @Override
    @Transactional(readOnly = true)
    public Order getOrder(String orderId, String userId) {
        // Input validation
        if (orderId == null || orderId.trim().isEmpty()) {
            throw new ValidationException("Order ID cannot be null or empty");
        }
        if (userId == null || userId.trim().isEmpty()) {
            throw new ValidationException("User ID cannot be null or empty");
        }

        log.debug("Retrieving order: {} for user: {}", orderId, userId);

        try {
            // Find and validate order
            Order order = orderRepository.findById(orderId)
                    .orElseThrow(() -> new ValidationException("Order not found with ID: " + orderId));

            // Authorization check - ensure user owns this order
            if (!order.getUserId().equals(userId)) {
                log.warn("Unauthorized access attempt - Order: {} does not belong to user: {}", orderId, userId);
                throw new ValidationException("You are not authorized to view this order");
            }

            return order;

        } catch (ValidationException e) {
            // Re-throw validation exceptions
            throw e;
        } catch (Exception e) {
            log.error("Unexpected error retrieving order: {} for user: {}: {}",
                    orderId, userId, e.getMessage(), e);
            throw new ValidationException("Failed to retrieve order: " + e.getMessage());
        }
    }

    @Override
    @Transactional(readOnly = true)
    public Order getOrderById(String orderId) {
        // Input validation
        if (orderId == null || orderId.trim().isEmpty()) {
            throw new ValidationException("Order ID cannot be null or empty");
        }

        log.debug("Retrieving order by ID: {}", orderId);

        try {
            return orderRepository.findById(orderId)
                    .orElseThrow(() -> new ValidationException("Order not found with ID: " + orderId));

        } catch (ValidationException e) {
            // Re-throw validation exceptions
            throw e;
        } catch (Exception e) {
            log.error("Unexpected error retrieving order by ID: {}: {}", orderId, e.getMessage(), e);
            throw new ValidationException("Failed to retrieve order: " + e.getMessage());
        }
    }

    @Override
    @Transactional(readOnly = true)
    public Page<Order> getUserOrders(String userId, Pageable pageable) {
        // Input validation
        if (userId == null || userId.trim().isEmpty()) {
            throw new ValidationException("User ID cannot be null or empty");
        }
        if (pageable == null) {
            throw new ValidationException("Pageable cannot be null");
        }

        log.debug("Retrieving orders for user: {} with pagination: {}", userId, pageable);

        try {
            // Validate user exists
            userServiceImpl.findById(userId);

            // Retrieve user's orders with pagination
            return orderRepository.findByUserIdOrderByCreatedAtDesc(userId, pageable);

        } catch (ValidationException e) {
            // Re-throw validation exceptions
            throw e;
        } catch (Exception e) {
            log.error("Unexpected error retrieving orders for user: {}: {}", userId, e.getMessage(), e);
            throw new ValidationException("Failed to retrieve user orders: " + e.getMessage());
        }
    }

    @Override
    @Transactional(readOnly = true)
    public Page<Order> getAllOrders(Pageable pageable) {
        // Input validation
        if (pageable == null) {
            throw new ValidationException("Pageable cannot be null");
        }

        log.debug("Retrieving all orders with pagination: {}", pageable);

        try {
            // Retrieve all orders with pagination (typically for admin use)
            return orderRepository.findAllByOrderByCreatedAtDesc(pageable);

        } catch (Exception e) {
            log.error("Unexpected error retrieving all orders: {}", e.getMessage(), e);
            throw new ValidationException("Failed to retrieve orders: " + e.getMessage());
        }
    }

    @Override
    @Transactional(readOnly = true)
    public boolean hasActivePurchase(String userId, String courseId) {
        // Input validation
        if (userId == null || userId.trim().isEmpty()) {
            return false;
        }
        if (courseId == null || courseId.trim().isEmpty()) {
            return false;
        }

        try {
            // Check if user has a verified order for this course
            boolean hasVerifiedOrder = orderRepository.existsByUserIdAndCourseIdAndStatus(
                    userId, courseId, OrderStatus.VERIFIED
            );

            log.debug("User {} has active purchase for course {}: {}", userId, courseId, hasVerifiedOrder);
            return hasVerifiedOrder;

        } catch (Exception e) {
            log.error("Error checking active purchase for user: {} and course: {}: {}",
                    userId, courseId, e.getMessage());
            return false; // Fail safely - deny access on error
        }
    }

    @Override
    @Transactional(readOnly = true)
    public List<String> getUserPurchasedCourseIds(String userId) {
        // Input validation
        if (userId == null || userId.trim().isEmpty()) {
            throw new ValidationException("User ID cannot be null or empty");
        }

        log.debug("Retrieving purchased course IDs for user: {}", userId);

        try {
            // Validate user exists
            userServiceImpl.findById(userId);

            // Find all verified orders for the user and extract course IDs
            List<Order> verifiedOrders = orderRepository.findByUserIdAndStatus(userId, OrderStatus.VERIFIED);

            List<String> courseIds = verifiedOrders.stream()
                    .map(Order::getCourseId)
                    .distinct() // Remove duplicates (in case of multiple orders for same course)
                    .collect(java.util.stream.Collectors.toList());

            log.debug("User {} has purchased {} courses: {}", userId, courseIds.size(), courseIds);
            return courseIds;

        } catch (ValidationException e) {
            // Re-throw validation exceptions
            throw e;
        } catch (Exception e) {
            log.error("Unexpected error retrieving purchased course IDs for user: {}: {}",
                    userId, e.getMessage(), e);
            throw new ValidationException("Failed to retrieve purchased courses: " + e.getMessage());
        }
    }

    @Override
    @Transactional(readOnly = true)
    public Page<Order> getOrdersByStatus(OrderStatus status, Pageable pageable) {
        if (status == null) {
            throw new ValidationException("Order status cannot be null");
        }
        if (pageable == null) {
            throw new ValidationException("Pageable cannot be null");
        }

        log.debug("Retrieving orders with status: {} and pagination: {}", status, pageable);

        try {
            return orderRepository.findByStatusOrderByCreatedAtDesc(status, pageable);
        } catch (Exception e) {
            log.error("Error retrieving orders by status {}: {}", status, e.getMessage(), e);
            throw new ValidationException("Failed to retrieve orders by status");
        }
    }

    @Override
    @Transactional(readOnly = true)
    public Page<Order> getPendingVerificationOrders(Pageable pageable) {
        if (pageable == null) {
            throw new ValidationException("Pageable cannot be null");
        }

        log.debug("Retrieving pending verification orders with pagination: {}", pageable);

        try {
            return orderRepository.findByStatusOrderByCreatedAtDesc(OrderStatus.SUBMITTED, pageable);
        } catch (Exception e) {
            log.error("Error retrieving pending verification orders: {}", e.getMessage(), e);
            throw new ValidationException("Failed to retrieve pending verification orders");
        }
    }

    @Override
    @Transactional(readOnly = true)
    public Page<Order> searchOrders(String userId, String courseId, OrderStatus status, PaymentMethod paymentMethod,
                                    String transactionId, String phoneNumber, String searchText, String dateFrom, String dateTo,
                                    Pageable pageable) {

        if (pageable == null) {
            throw new ValidationException("Pageable cannot be null");
        }

        log.debug("Searching orders with filters - userId: {}, courseId: {}, status: {}, paymentMethod: {}, " +
                        "transactionId: {}, phoneNumber: {}, searchText: {}, dateFrom: {}, dateTo: {}",
                userId, courseId, status, paymentMethod, transactionId, phoneNumber, searchText, dateFrom, dateTo);

        try {
            // Parse and normalize date inputs
            java.time.Instant dateFromInstant = parseDateString(dateFrom);
            java.time.Instant dateToInstant = parseDateStringAsEndOfDay(dateTo);

            // Normalize string inputs (trim and convert empty strings to null)
            String normalizedUserId = normalizeString(userId);
            String normalizedCourseId = normalizeString(courseId);
            String normalizedTransactionId = normalizeString(transactionId);
            String normalizedPhoneNumber = normalizeString(phoneNumber);
            String normalizedSearchText = normalizeString(searchText);

            // Use the generalized search query that handles all combinations dynamically
            return orderRepository.searchOrders(
                    normalizedUserId,
                    normalizedCourseId,
                    status,
                    paymentMethod,
                    normalizedTransactionId,
                    normalizedPhoneNumber,
                    normalizedSearchText,
                    dateFromInstant,
                    dateToInstant,
                    pageable
            );

        } catch (ValidationException e) {
            throw e;
        } catch (Exception e) {
            log.error("Error searching orders: {}", e.getMessage(), e);
            throw new ValidationException("Failed to search orders: " + e.getMessage());
        }
    }


    @Override
    @Transactional(readOnly = true)
    public BigDecimal getCourseRevenue(String courseId) {
        // Input validation
        if (courseId == null || courseId.trim().isEmpty()) {
            throw new ValidationException("Course ID cannot be null or empty");
        }

        log.debug("Calculating revenue for course: {}", courseId);

        try {
            // Validate course exists
            courseService.getCourse(courseId);

            // Get all verified orders for this course
            List<Order> verifiedOrders = orderRepository.findByCourseIdAndStatusVerified(courseId);

            // Calculate total revenue
            BigDecimal totalRevenue = verifiedOrders.stream()
                    .map(Order::getTotalAmount)
                    .filter(amount -> amount != null)
                    .reduce(BigDecimal.ZERO, BigDecimal::add);

            log.debug("Course {} has generated revenue: {} from {} orders",
                    courseId, totalRevenue, verifiedOrders.size());

            return totalRevenue;

        } catch (ValidationException e) {
            throw e;
        } catch (Exception e) {
            log.error("Error calculating revenue for course {}: {}", courseId, e.getMessage(), e);
            throw new ValidationException("Failed to calculate course revenue: " + e.getMessage());
        }
    }

    @Override
    @Transactional(readOnly = true)
    public OrderStatistics getOrderStatistics() {
        log.debug("Calculating order statistics");

        try {
            // Count orders by status
            long totalOrders = orderRepository.count();
            long pendingPayment = orderRepository.countByStatus(OrderStatus.PENDING);
            long pendingVerification = orderRepository.countByStatus(OrderStatus.SUBMITTED);
            long completed = orderRepository.countByStatus(OrderStatus.VERIFIED);
            long rejected = orderRepository.countByStatus(OrderStatus.REJECTED);

            // Calculate cancelled orders (we treat REJECTED with user cancellation reason as cancelled)
            // For now, we'll count all REJECTED as rejected since we don't have separate CANCELLED status
            long cancelled = 0; // This could be enhanced to filter REJECTED orders by rejection reason

            // Calculate total revenue from verified orders
            List<Order> verifiedOrders = orderRepository.findVerifiedOrdersForRevenue();
            BigDecimal totalRevenue = verifiedOrders.stream()
                    .map(Order::getTotalAmount)
                    .filter(amount -> amount != null)
                    .reduce(BigDecimal.ZERO, BigDecimal::add);

            OrderStatistics stats = new OrderStatistics(
                    totalOrders,
                    pendingPayment,
                    pendingVerification,
                    completed,
                    rejected,
                    cancelled,
                    totalRevenue
            );

            log.debug("Order statistics: Total={}, Pending={}, Submitted={}, Verified={}, Rejected={}, Revenue={}",
                    totalOrders, pendingPayment, pendingVerification, completed, rejected, totalRevenue);

            return stats;

        } catch (Exception e) {
            log.error("Error calculating order statistics: {}", e.getMessage(), e);
            throw new ValidationException("Failed to calculate order statistics: " + e.getMessage());
        }
    }

    @Override
    @Transactional(readOnly = true)
    public List<DailyOrderSummary> getDailyOrderSummary(int days) {
        // Input validation
        if (days <= 0) {
            throw new ValidationException("Days must be a positive number");
        }
        if (days > 365) {
            throw new ValidationException("Cannot retrieve more than 365 days of data");
        }

        log.debug("Generating daily order summary for {} days", days);

        try {
            List<DailyOrderSummary> summaries = new java.util.ArrayList<>();
            java.time.LocalDate currentDate = java.time.LocalDate.now();

            for (int i = 0; i < days; i++) {
                java.time.LocalDate date = currentDate.minusDays(i);

                // Calculate start and end of day in UTC
                java.time.Instant startOfDay = date.atStartOfDay(java.time.ZoneOffset.UTC).toInstant();
                java.time.Instant endOfDay = date.plusDays(1).atStartOfDay(java.time.ZoneOffset.UTC).toInstant();

                // Get orders for this day
                List<Order> dayOrders = orderRepository.findOrdersBetweenDates(startOfDay, endOfDay);

                // Calculate metrics
                long orderCount = dayOrders.size();

                // Calculate revenue from verified orders only
                BigDecimal dayRevenue = dayOrders.stream()
                        .filter(order -> order.getStatus() == OrderStatus.VERIFIED)
                        .map(Order::getTotalAmount)
                        .filter(amount -> amount != null)
                        .reduce(BigDecimal.ZERO, BigDecimal::add);

                // Count new customers (users with their first order on this day)
                // This is a simplified approach - for production, you'd need more sophisticated logic
                long newCustomers = dayOrders.stream()
                        .map(Order::getUserId)
                        .distinct()
                        .count();

                DailyOrderSummary summary = new DailyOrderSummary(
                        date.toString(),
                        orderCount,
                        dayRevenue,
                        newCustomers
                );

                summaries.add(summary);
            }

            log.debug("Generated daily order summary for {} days", days);
            return summaries;

        } catch (ValidationException e) {
            throw e;
        } catch (Exception e) {
            log.error("Error generating daily order summary: {}", e.getMessage(), e);
            throw new ValidationException("Failed to generate daily order summary: " + e.getMessage());
        }
    }

    @Override
    @Transactional
    public int processExpiredOrders() {
        log.info("Processing expired orders");

        try {
            // Define expiry threshold (e.g., orders pending for more than 24 hours)
            java.time.Instant expiryThreshold = java.time.Instant.now().minus(24, java.time.temporal.ChronoUnit.HOURS);

            // Find expired pending orders
            List<Order> expiredOrders = orderRepository.findExpiredPendingOrders(expiryThreshold);

            int expiredCount = 0;

            for (Order order : expiredOrders) {
                try {
                    // Update order status to REJECTED
                    order.setStatus(OrderStatus.REJECTED);
                    order.setRejectionReason("Order expired - no payment submitted within 24 hours");
                    order.setAdminNote("Auto-expired by system");
                    order.setVerifiedAt(java.time.Instant.now());

                    orderRepository.save(order);
                    expiredCount++;

                    log.debug("Expired order: {} for user: {}", order.getId(), order.getUserId());

                } catch (Exception e) {
                    log.error("Failed to expire order {}: {}", order.getId(), e.getMessage());
                    // Continue processing other orders even if one fails
                }
            }

            log.info("Processed {} expired orders", expiredCount);

            // TODO: Optionally send notifications to users about expired orders

            return expiredCount;

        } catch (Exception e) {
            log.error("Error processing expired orders: {}", e.getMessage(), e);
            throw new ValidationException("Failed to process expired orders: " + e.getMessage());
        }
    }


    /**
     * Normalize string input - trim whitespace and convert empty strings to null
     */
    private String normalizeString(String input) {
        if (input == null) {
            return null;
        }
        String trimmed = input.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }

    /**
     * Parse date string to Instant for start date (beginning of day if only date provided)
     */
    private java.time.Instant parseDateString(String dateStr) {
        if (dateStr == null || dateStr.trim().isEmpty()) {
            return null;
        }

        try {
            String trimmed = dateStr.trim();

            // If only date provided (YYYY-MM-DD), set to start of day
            if (trimmed.matches("\\d{4}-\\d{2}-\\d{2}")) {
                return java.time.LocalDate.parse(trimmed)
                        .atStartOfDay(java.time.ZoneOffset.UTC)
                        .toInstant();
            }

            // Parse as ISO instant
            return java.time.Instant.parse(trimmed);

        } catch (Exception e) {
            log.warn("Invalid date format: {}. Expected YYYY-MM-DD or ISO format. Ignoring date filter.", dateStr);
            return null;
        }
    }

    /**
     * Parse date string to Instant for end date (end of day if only date provided)
     */
    private java.time.Instant parseDateStringAsEndOfDay(String dateStr) {
        if (dateStr == null || dateStr.trim().isEmpty()) {
            return null;
        }

        try {
            String trimmed = dateStr.trim();

            // If only date provided (YYYY-MM-DD), set to end of day
            if (trimmed.matches("\\d{4}-\\d{2}-\\d{2}")) {
                return java.time.LocalDate.parse(trimmed)
                        .atTime(23, 59, 59, 999_999_999)
                        .atZone(java.time.ZoneOffset.UTC)
                        .toInstant();
            }

            // Parse as ISO instant
            return java.time.Instant.parse(trimmed);

        } catch (Exception e) {
            log.warn("Invalid date format: {}. Expected YYYY-MM-DD or ISO format. Ignoring date filter.", dateStr);
            return null;
        }
    }


    private BigDecimal calculateDiscountedPrice(BigDecimal discountPrice, String courseId, BigDecimal coursePrice) {
        if (discountPrice == null || discountPrice.compareTo(BigDecimal.ZERO) <= 0) {
            return BigDecimal.ZERO;
        }

        try {
            return coursePrice.subtract(discountPrice);
        } catch (Exception e) {
            log.warn("Invalid discount price: {} for course: {}. Error: {}", discountPrice, courseId, e.getMessage());
            return BigDecimal.ZERO; // Invalid discount prices are ignored, not failed
        }
    }
}