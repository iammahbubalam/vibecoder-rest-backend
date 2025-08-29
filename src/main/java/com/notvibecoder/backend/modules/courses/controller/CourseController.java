package com.notvibecoder.backend.modules.courses.controller;

import com.notvibecoder.backend.core.dto.ApiResponse;
import com.notvibecoder.backend.modules.admin.constants.SecurityConstants;
import com.notvibecoder.backend.modules.auth.security.UserPrincipal;
import com.notvibecoder.backend.modules.courses.entity.Course;
import com.notvibecoder.backend.modules.courses.service.CourseService;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * Course Controller demonstrating centralized security configuration
 * 
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
    @GetMapping("/public")
    public ResponseEntity<ApiResponse<List<Course>>> getPublicCourses() {
        List<Course> courses = courseService.getPublishedCourses();
        return ResponseEntity.ok(ApiResponse.success("Public courses retrieved", courses));
    }

    /**
     * Get course details - no authentication for public courses
     */
    @GetMapping("/{courseId}/public")
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
  
    /**
     * Access course content - requires course purchase or admin
     */
    @GetMapping("/{courseId}/content")
    @PreAuthorize(SecurityConstants.CAN_ACCESS_COURSE)
    public ResponseEntity<ApiResponse<Course>> getCourseContent(@PathVariable String courseId) {
        Course course = courseService.getCourseWithContent(courseId);
        return ResponseEntity.ok(ApiResponse.success("Course content retrieved", course));
    }

    // ==================== TEACHER/ADMIN ENDPOINTS ====================
    
    /**
     * Create new course - requires teacher or admin role
     */
    @PostMapping
    @PreAuthorize(SecurityConstants.CAN_CREATE_COURSES)
    public ResponseEntity<ApiResponse<Course>> createCourse(
            @RequestBody Course course,
            @AuthenticationPrincipal UserPrincipal principal) {
        Course createdCourse = courseService.createCourse(course, principal.getId());
        return ResponseEntity.ok(ApiResponse.success("Course created successfully", createdCourse));
    }

    /**
     * Update course - requires ownership or admin
     */
    @PutMapping("/{courseId}")
    @PreAuthorize("@securityService.canManageCourse(#courseId, #course.instructorId)")
    public ResponseEntity<ApiResponse<Course>> updateCourse(
            @PathVariable String courseId,
            @RequestBody Course course) {
        Course updatedCourse = courseService.updateCourse(courseId, course);
        return ResponseEntity.ok(ApiResponse.success("Course updated successfully", updatedCourse));
    }

    /**
     * Delete course - requires ownership or admin
     */
    @DeleteMapping("/{courseId}")
    @PreAuthorize("@securityService.isAdmin() or @courseService.isInstructor(#courseId, authentication.principal.id)")
    public ResponseEntity<ApiResponse<Void>> deleteCourse(@PathVariable String courseId) {
        courseService.deleteCourse(courseId);
        return ResponseEntity.ok(ApiResponse.success("Course deleted successfully", null));
    }

    // ==================== ADMIN ONLY ENDPOINTS ====================
    
    /**
     * Get all courses (including unpublished) - admin only
     */
    @GetMapping("/admin/all")
    @PreAuthorize(SecurityConstants.HAS_ROLE_ADMIN)
    public ResponseEntity<ApiResponse<List<Course>>> getAllCourses() {
        List<Course> courses = courseService.getAllCourses();
        return ResponseEntity.ok(ApiResponse.success("All courses retrieved", courses));
    }

    /**
     * Approve/publish course - admin only
     */
    @PostMapping("/{courseId}/approve")
    @PreAuthorize(SecurityConstants.HAS_ROLE_ADMIN)
    public ResponseEntity<ApiResponse<Course>> approveCourse(@PathVariable String courseId) {
        Course course = courseService.approveCourse(courseId);
        return ResponseEntity.ok(ApiResponse.success("Course approved successfully", course));
    }
}
