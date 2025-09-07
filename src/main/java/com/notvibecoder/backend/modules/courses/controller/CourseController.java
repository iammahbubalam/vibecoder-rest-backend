package com.notvibecoder.backend.modules.courses.controller;

import com.notvibecoder.backend.core.dto.ApiResponse;
import com.notvibecoder.backend.core.exception.ValidationException;
import com.notvibecoder.backend.modules.auth.security.UserPrincipal;
import com.notvibecoder.backend.modules.courses.entity.Course;
import com.notvibecoder.backend.modules.courses.entity.CourseStatus;
import com.notvibecoder.backend.modules.courses.entity.VideoLesson;
import com.notvibecoder.backend.modules.courses.service.CourseService;
import com.notvibecoder.backend.modules.system.constants.SecurityConstants;
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
 * Course Controller - Complete Course Management API
 * <p>
 * This controller provides comprehensive course management functionality:
 * 
 * PUBLIC ENDPOINTS (No Authentication Required):
 * - GET /api/v1/courses/ - Browse published courses
 * - GET /api/v1/courses/{courseId}/ - Get public course details
 * - GET /api/v1/courses/{courseId}/preview-lessons - Get free preview lessons
 * 
 * USER ENDPOINTS (Authentication Required):
 * - GET /api/v1/courses/my-courses - Get user's purchased courses
 * 
 * USER ENDPOINTS (Authentication + Course Purchase Required):
 * - GET /api/v1/courses/{courseId}/content - Get full course content (requires purchase)
 * - GET /api/v1/courses/{courseId}/lessons - Get all lessons (requires purchase)
 * - GET /api/v1/courses/{courseId}/lessons/{lessonId} - Get specific lesson details (requires purchase)
 * 
 * ADMIN ENDPOINTS (Admin Role Required):
 * - POST /api/v1/courses - Create new course
 * - PUT /api/v1/courses/{courseId} - Update course details
 * - DELETE /api/v1/courses/{courseId} - Delete course
 * - POST /api/v1/courses/{courseId}/lessons - Add lessons to course
 * - PUT /api/v1/courses/{courseId}/lessons/{lessonId} - Update specific lesson
 * - DELETE /api/v1/courses/{courseId}/lessons/{lessonId} - Delete specific lesson
 * - GET /api/v1/courses/admin/all - Get all courses (including drafts)
 * - PUT /api/v1/courses/admin/{courseId}/status - Update course status
 * - GET /api/v1/courses/admin/{courseId}/published - Check if course is published
 * 
 * Security Model:
 * - Public: Course browsing and free previews
 * - Authenticated Users: Access to their own profile and purchased courses
 * - Course Purchase Verification: Required for accessing course content and lessons
 * - Admin: Full course and lesson management + bypass purchase requirements
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
    @GetMapping()
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
    @PreAuthorize(SecurityConstants.USER_PROFILE_ACCESS)
    public ResponseEntity<ApiResponse<List<Course>>> getMyCourses(
            @AuthenticationPrincipal UserPrincipal principal) {
        List<Course> courses = courseService.getUserCourses(principal.getId());
        return ResponseEntity.ok(ApiResponse.success("My courses retrieved", courses));
    }


    @GetMapping("/{courseId}/content")
    @PreAuthorize(SecurityConstants.COURSE_CONTENT_ACCESS)
    public ResponseEntity<ApiResponse<Course>> getCourseContent(@PathVariable String courseId) {
        Course course = courseService.getCourse(courseId);
        return ResponseEntity.ok(ApiResponse.success("Course content retrieved", course));
    }

    /**
     * Get free preview lessons for a course - no authentication required
     */
    @GetMapping("/{courseId}/preview-lessons")
    public ResponseEntity<ApiResponse<List<VideoLesson>>> getFreePreviewLessons(@PathVariable String courseId) {
        List<VideoLesson> lessons = courseService.getVideoLessonsWithFreePreview(courseId);
        return ResponseEntity.ok(ApiResponse.success("Free preview lessons retrieved", lessons));
    }

    /**
     * Get all lessons for a course - requires authentication and course access
     */
    @GetMapping("/{courseId}/lessons")
    @PreAuthorize(SecurityConstants.LESSON_ACCESS)
    public ResponseEntity<ApiResponse<List<VideoLesson>>> getAllLessons(@PathVariable String courseId) {
        List<VideoLesson> lessons = courseService.getAllLessonsByCourseId(courseId);
        return ResponseEntity.ok(ApiResponse.success("Course lessons retrieved", lessons));
    }

    /**
     * Get specific lesson details - requires authentication and course access
     */
    @GetMapping("/{courseId}/lessons/{lessonId}")
    @PreAuthorize(SecurityConstants.LESSON_ACCESS)
    public ResponseEntity<ApiResponse<VideoLesson>> getVideoLesson(
            @PathVariable String courseId,
            @PathVariable String lessonId) {
        VideoLesson lesson = courseService.getVideoLesson(courseId, lessonId);
        return ResponseEntity.ok(ApiResponse.success("Video lesson retrieved", lesson));
    }

    /**
     * Update specific lesson - admin only
     */
    @PutMapping("/{courseId}/lessons/{lessonId}")
    @PreAuthorize(SecurityConstants.COURSE_UPDATE)
    public ResponseEntity<ApiResponse<VideoLesson>> updateVideoLesson(
            @PathVariable String courseId,
            @PathVariable String lessonId,
            @Valid @RequestBody VideoLesson lesson,
            @AuthenticationPrincipal UserPrincipal principal) {
        
        log.info("User {} is updating lesson {} for course {}", 
                principal.getUsername(), lessonId, courseId);
        
        VideoLesson updatedLesson = courseService.updateVideoLesson(courseId, lessonId, lesson);
        return ResponseEntity.ok(ApiResponse.success("Video lesson updated successfully", updatedLesson));
    }

    /**
     * Delete specific lesson - admin only
     */
    @DeleteMapping("/{courseId}/lessons/{lessonId}")
    @PreAuthorize(SecurityConstants.COURSE_DELETE)
    public ResponseEntity<ApiResponse<Void>> deleteVideoLesson(
            @PathVariable String courseId,
            @PathVariable String lessonId,
            @AuthenticationPrincipal UserPrincipal principal) {
        
        log.info("User {} is deleting lesson {} from course {}", 
                principal.getUsername(), lessonId, courseId);
        
        courseService.deleteVideoLesson(courseId, lessonId);
        return ResponseEntity.ok(ApiResponse.success("Video lesson deleted successfully", null));
    }


    @PostMapping("/{courseId}/lessons")
    @PreAuthorize(SecurityConstants.COURSE_CREATE)
    public ResponseEntity<ApiResponse<List<VideoLesson>>> createVideoLessons(
            @PathVariable String courseId,
            @Valid @RequestBody List<VideoLesson> lessons,
            @AuthenticationPrincipal UserPrincipal principal) {

        log.info("User {} is creating {} video lessons for course: {}",
                principal.getName(), lessons.size(), courseId);
        try {
            List<VideoLesson> createdLessons = courseService.saveVideoLessonsAndUpdateCourse(courseId, lessons);
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
    @PreAuthorize(SecurityConstants.COURSE_CREATE)
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
     * Update course - requires admin access
     */
    @PutMapping("/{courseId}")
    @PreAuthorize(SecurityConstants.COURSE_UPDATE)
    public ResponseEntity<ApiResponse<Course>> updateCourse(
            @PathVariable String courseId,
            @RequestBody Course course) {
        log.info("Updating course with ID: {}", courseId);
        Course updatedCourse = courseService.updateCourse(courseId, course);
        return ResponseEntity.ok(ApiResponse.success("Course updated successfully", updatedCourse));
    }

    /**
     * Delete course - requires admin access
     */
    @DeleteMapping("/{courseId}")
    @PreAuthorize(SecurityConstants.COURSE_DELETE)
    public ResponseEntity<ApiResponse<Void>> deleteCourse(@PathVariable String courseId) {
        courseService.deleteCourse(courseId);
        return ResponseEntity.ok(ApiResponse.success("Course deleted successfully", null));
    }

    // ==================== ADMIN ONLY ENDPOINTS ====================

    /**
     * Get all courses for admin - includes drafts and unpublished
     */
    @GetMapping("/admin/all")
    @PreAuthorize(SecurityConstants.COURSE_ADMIN_VIEW)
    public ResponseEntity<ApiResponse<List<Course>>> getAllCourses() {
        List<Course> courses = courseService.getAllCourses();
        return ResponseEntity.ok(ApiResponse.success("All courses retrieved", courses));
    }

    /**
     * Update course status - admin only
     */
    @PutMapping("/admin/{courseId}/status")
    @PreAuthorize(SecurityConstants.COURSE_UPDATE)
    public ResponseEntity<ApiResponse<Void>> updateCourseStatus(
            @PathVariable String courseId,
            @RequestParam CourseStatus status,
            @AuthenticationPrincipal UserPrincipal principal) {
        
        log.info("User {} is updating status of course {} to {}", 
                principal.getUsername(), courseId, status);
        
        courseService.updateCourseStatus(courseId, status);
        return ResponseEntity.ok(ApiResponse.success("Course status updated successfully", null));
    }

    /**
     * Check if course is published - admin utility endpoint
     */
    @GetMapping("/admin/{courseId}/published")
    @PreAuthorize(SecurityConstants.COURSE_ADMIN_VIEW)
    public ResponseEntity<ApiResponse<Course>> isCoursePublished(@PathVariable String courseId) {
        Course course = courseService.isCoursePublished(courseId);
        return ResponseEntity.ok(ApiResponse.success("Course publish status retrieved", course));
    }

}
