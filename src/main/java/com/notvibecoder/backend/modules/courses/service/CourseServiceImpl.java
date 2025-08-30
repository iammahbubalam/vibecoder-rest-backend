package com.notvibecoder.backend.modules.courses.service;

import com.notvibecoder.backend.core.exception.CourseCreationException;
import com.notvibecoder.backend.core.exception.ValidationException;
import com.notvibecoder.backend.modules.courses.entity.Course;
import com.notvibecoder.backend.modules.courses.entity.CourseStatus;
import com.notvibecoder.backend.modules.courses.entity.VideoLesson;
import com.notvibecoder.backend.modules.courses.repository.CourseRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataAccessException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.List;

@Service
@RequiredArgsConstructor
@Slf4j
public class CourseServiceImpl implements CourseService {
    private final CourseRepository courseRepository;
    private final VideoLessonService videoLessonService;

    @Override
    public List<Course> getPublishedCourses() {
        return List.of();
    }

    @Override
    public Course getPublicCourseDetails(String courseId) {
        return null;
    }

    @Override
    public List<Course> getUserCourses(String id) {
        return List.of();
    }

    @Override
    public Course getCourseWithContent(String courseId) {
        return null;
    }

    @Override
    @Transactional
    public Course createCourse(Course course) {
        course.setStatus(CourseStatus.DRAFT);
        course.setEnrollmentCount(0L);
        course.setTotalLessons(0);
        course.setCreatedAt(Instant.now());
        if (course.getPrice() != null && course.getPrice().compareTo(BigDecimal.ZERO) < 0) {
            throw new ValidationException("Price cannot be negative");
        }
        try {
            Course savedCourse = courseRepository.save(course);
            log.info("Course created successfully with ID: {}", savedCourse.getId());
            return savedCourse;

        } catch (DataAccessException e) {
            log.error("Failed to create course: {}", e.getMessage());
            throw new CourseCreationException("Failed to create course", e);
        }
        }
    @Override
    @Transactional
    public Course updateCourse(String courseId, Course course) {
        // Input validation
        if (courseId == null || courseId.trim().isEmpty()) {
            throw new ValidationException("Course ID cannot be null or empty");
        }

        if (course == null) {
            throw new ValidationException("Course data cannot be null");
        }

        if (course.getPrice() != null && course.getPrice().compareTo(BigDecimal.ZERO) < 0) {
            throw new ValidationException("Price cannot be negative");
        }

        try {
            // Fetch existing course first
            Course existingCourse = courseRepository.findById(courseId)
                    .orElseThrow(() -> new ValidationException("Course not found with ID: " + courseId));

            // Update course fields with null-safe operations
            updateCourseFields(existingCourse, course);
            // Set update timestamp
            existingCourse.setUpdatedAt(Instant.now());

            // Save and return updated course
            Course updatedCourse = courseRepository.save(existingCourse);
            log.info("Course updated successfully with ID: {}, Total lessons: {}, Total duration: {} minutes",
                    updatedCourse.getId(), updatedCourse.getTotalLessons(), updatedCourse.getTotalDurationMinutes());

            return updatedCourse;

        } catch (DataAccessException e) {
            log.error("Failed to update course with ID {}: {}", courseId, e.getMessage());
            throw new CourseCreationException("Failed to update course", e);
        } catch (Exception e) {
            log.error("Unexpected error while updating course with ID {}: {}", courseId, e.getMessage());
            throw new CourseCreationException("Unexpected error occurred while updating course", e);
        }
    }

    @Override
    public List<VideoLesson> createVideoLesson(String courseId, List<VideoLesson> lessons) {

        return  videoLessonService.creatVideoLesson(courseId,lessons);
    }

    @Override
public void deleteCourse(String courseId) {
    try {
        courseRepository.deleteById(courseId);
        log.info("Course deleted successfully with ID: {}", courseId);
    } catch (DataAccessException e) {
        log.error("Failed to delete course with ID {}: {}", courseId, e.getMessage());
        throw new CourseCreationException("Failed to delete course", e);
    } catch (Exception e) {
        log.error("Unexpected error while deleting course with ID {}: {}", courseId, e.getMessage());
        throw new CourseCreationException("Unexpected error occurred while deleting course", e);
    }
}

@Override
public List<Course> getAllCourses() {
    try {
        return courseRepository.findAll();
    } catch (DataAccessException e) {
        log.error("Failed to retrieve all courses: {}", e.getMessage());
        throw new CourseCreationException("Failed to retrieve all courses", e);
    } catch (Exception e) {
        log.error("Unexpected error while retrieving all courses: {}", e.getMessage());
        throw new CourseCreationException("Unexpected error occurred while retrieving all courses", e);
    }
}


private void updateCourseFields(Course existingCourse, Course updatedCourse) {
    // Only update fields that are not null in the incoming course
    if (updatedCourse.getTitle() != null) {
        existingCourse.setTitle(updatedCourse.getTitle());
    }
    
    if (updatedCourse.getDescription() != null) {
        existingCourse.setDescription(updatedCourse.getDescription());
    }
    
    if (updatedCourse.getShortDescription() != null) {
        existingCourse.setShortDescription(updatedCourse.getShortDescription());
    }
    
    if (updatedCourse.getInstructorName() != null) {
        existingCourse.setInstructorName(updatedCourse.getInstructorName());
    }
    
    if (updatedCourse.getPrice() != null) {
        existingCourse.setPrice(updatedCourse.getPrice());
    }
    
    if (updatedCourse.getThumbnailUrl() != null) {
        existingCourse.setThumbnailUrl(updatedCourse.getThumbnailUrl());
    }
    
    if (updatedCourse.getPreviewVideoUrl() != null) {
        existingCourse.setPreviewVideoUrl(updatedCourse.getPreviewVideoUrl());
    }
    
    if (updatedCourse.getStatus() != null) {
        existingCourse.setStatus(updatedCourse.getStatus());
    }
    
    if (updatedCourse.getWhatYouWillLearn() != null) {
        existingCourse.setWhatYouWillLearn(updatedCourse.getWhatYouWillLearn());
    }
    
    if (updatedCourse.getRequirements() != null) {
        existingCourse.setRequirements(updatedCourse.getRequirements());
    }
    
    if (updatedCourse.getCategory() != null) {
        existingCourse.setCategory(updatedCourse.getCategory());
    }
    
    if (updatedCourse.getTags() != null) {
        existingCourse.setTags(updatedCourse.getTags());
    }
}

}
