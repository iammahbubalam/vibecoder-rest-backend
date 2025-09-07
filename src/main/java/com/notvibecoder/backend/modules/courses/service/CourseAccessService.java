package com.notvibecoder.backend.modules.courses.service;

import com.notvibecoder.backend.modules.user.entity.User;
import com.notvibecoder.backend.modules.user.service.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

/**
 * Service to handle course access verification
 * Checks if a user has purchased or has access to a specific course
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class CourseAccessService {

    private final UserService userService;

    /**
     * Check if a user has access to a course
     * This could be through purchase, enrollment, or other business rules
     * 
     * @param userId The user ID
     * @param courseId The course ID
     * @return true if user has access, false otherwise
     */
    public boolean hasAccess(String userId, String courseId) {
        try {
            log.debug("Checking course access for user {} and course {}", userId, courseId);
            
            // Get the user and check if they have purchased the course
            User user = userService.findById(userId);
            
            // Check if the course ID is in the user's purchased courses list
            boolean hasAccess = user.getPurchasedCourseIds() != null && 
                               user.getPurchasedCourseIds().contains(courseId);
            
            log.debug("User {} {} access to course {}", 
                     userId, hasAccess ? "HAS" : "DOES NOT HAVE", courseId);
            
            return hasAccess;
            
        } catch (Exception e) {
            log.error("Error checking course access for user {} and course {}: {}", 
                     userId, courseId, e.getMessage());
            // In case of error, deny access for security
            return false;
        }
    }

    /**
     * Check if a user has access to any lesson in a course
     * Currently same logic as course access, but could be extended
     * for lesson-specific access control
     * 
     * @param userId The user ID
     * @param courseId The course ID
     * @return true if user has lesson access, false otherwise
     */
    public boolean hasLessonAccess(String userId, String courseId) {
        return hasAccess(userId, courseId);
    }
}
