package com.notvibecoder.backend.modules.courses.controller;

import com.notvibecoder.backend.core.dto.ApiResponse;
import com.notvibecoder.backend.core.exception.ValidationException;
import com.notvibecoder.backend.modules.admin.constants.SecurityConstants;
import com.notvibecoder.backend.modules.auth.security.UserPrincipal;
import com.notvibecoder.backend.modules.courses.entity.Course;
import com.notvibecoder.backend.modules.courses.entity.VideoLesson;
import com.notvibecoder.backend.modules.courses.service.CourseService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * Course Controller demonstrating centralized security configuration
 * <p>
 * Shows best practices for different authorization levels:
 * - Public endpoints (no authentication)
 * - User endpoints (basic authentication)
 * - Role-based endpoints (specific roles)
 * - Resource-based endpoints (ownership checks)
 */
@RestController
@RequestMapping("/api/v1/courses")
@RequiredArgsConstructor
@Slf4j
public class CourseController {

    private final CourseService courseService;


    // ==================== PUBLIC ENDPOINTS ====================

    /**
     * Public course browsing - no authentication required
     */
    @GetMapping("/")
    public ResponseEntity<ApiResponse<List<Course>>> getPublicCourses() {
        List<Course> courses = courseService.getPublishedCourses();
        return ResponseEntity.ok(ApiResponse.success("Public courses retrieved", courses));
    }

    /**
     * Get course details - no authentication for public courses
     */
    @GetMapping("/{courseId}/")
    public ResponseEntity<ApiResponse<Course>> getPublicCourseDetails(@PathVariable String courseId) {
        Course course = courseService.getPublicCourseDetails(courseId);
        return ResponseEntity.ok(ApiResponse.success("Course details retrieved", course));
    }

    // ==================== USER ENDPOINTS ====================

    /**
     * Get user's purchased courses - requires authentication
     */
    @GetMapping("/my-courses")
    @PreAuthorize(SecurityConstants.IS_AUTHENTICATED)
    public ResponseEntity<ApiResponse<List<Course>>> getMyCourses(
            @AuthenticationPrincipal UserPrincipal principal) {
        List<Course> courses = courseService.getUserCourses(principal.getId());
        return ResponseEntity.ok(ApiResponse.success("My courses retrieved", courses));
    }


    @GetMapping("/{courseId}/content")
    @PreAuthorize(SecurityConstants.CAN_ACCESS_COURSE)
    public ResponseEntity<ApiResponse<Course>> getCourseContent(@PathVariable String courseId) {
        Course course = courseService.getCourseWithContent(courseId);
        return ResponseEntity.ok(ApiResponse.success("Course content retrieved", course));
    }


    @PostMapping("/{courseId}/lessons")
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    public ResponseEntity<ApiResponse<List<VideoLesson>>> createVideoLessons(
            @PathVariable String courseId,
            @Valid @RequestBody List<VideoLesson> lessons,
            @AuthenticationPrincipal UserPrincipal principal) {

        log.info("User {} is creating {} video lessons for course: {}",
                principal.getName(), lessons.size(), courseId);
        try {
            List<VideoLesson> createdLessons = courseService.createVideoLesson(courseId, lessons);
            return ResponseEntity.status(HttpStatus.CREATED)
                    .body(ApiResponse.success("Video lessons created successfully", createdLessons));
        } catch (IllegalArgumentException e) {
            log.warn("Validation error creating video lessons for course {}: {}", courseId, e.getMessage());
            return ResponseEntity.badRequest()
                    .body(ApiResponse.error("Validation failed: " + e.getMessage(), "VALIDATION_ERROR"));
        } catch (RuntimeException e) {
            log.error("Error creating video lessons for course {}: {}", courseId, e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponse.error("Failed to create video lessons", "CREATION_ERROR"));
        }
    }

    @PostMapping()
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    public ResponseEntity<ApiResponse<Course>> createCourse(
            @Valid @RequestBody Course Course, @AuthenticationPrincipal UserPrincipal principal) {

        log.info("User {} is creating a course", principal.getUsername());
        log.info("UserPrincipal: {}", principal.getAuthorities());
        try {
            Course createdCourse = courseService.createCourse(Course);
            return ResponseEntity.status(HttpStatus.CREATED)
                    .body(ApiResponse.success("Course created successfully", createdCourse));
        } catch (ValidationException e) {
            return ResponseEntity.badRequest()
                    .body(ApiResponse.error("Validation failed: " + e.getMessage(), e.getErrorCode()));
        }
    }

    /**
     * Update course - requires ownership or admin
     */
    @PutMapping("/{courseId}")
    public ResponseEntity<ApiResponse<Course>> updateCourse(
            @PathVariable String courseId,
            @RequestBody Course course) {
        log.info("Updating course with ID: {}", courseId);
        Course updatedCourse = courseService.updateCourse(courseId, course);
        return ResponseEntity.ok(ApiResponse.success("Course updated successfully", updatedCourse));
    }

    /**
     * Delete course - requires ownership or admin
     */
    @DeleteMapping("/{courseId}")
    public ResponseEntity<ApiResponse<Void>> deleteCourse(@PathVariable String courseId) {
        courseService.deleteCourse(courseId);
        return ResponseEntity.ok(ApiResponse.success("Course deleted successfully", null));
    }

    // ==================== ADMIN ONLY ENDPOINTS ====================

    @GetMapping("/admin/all")
    public ResponseEntity<ApiResponse<List<Course>>> getAllCourses() {
        List<Course> courses = courseService.getAllCourses();
        return ResponseEntity.ok(ApiResponse.success("All courses retrieved", courses));
    }

}
