package com.notvibecoder.backend.modules.courses.service;

import com.notvibecoder.backend.core.exception.ValidationException;
import com.notvibecoder.backend.core.exception.course.CourseNotFoundException;
import com.notvibecoder.backend.core.exception.course.LessonNotFoundException;
import com.notvibecoder.backend.core.exception.system.DatabaseException;
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
        return courseRepository.findByStatus(CourseStatus.PUBLISHED);
    }

    @Override
    public Course isCoursePublished(String courseId) {
        return courseRepository.findByIdAndStatus(courseId, CourseStatus.PUBLISHED);
    }

    @Override
    public void updateCourseStatus(String courseId, CourseStatus status) {
        Course course = courseRepository.findById(courseId)
                .orElseThrow(() -> new CourseNotFoundException(courseId));
        course.setStatus(status);
        courseRepository.save(course);
    }

    @Override
    public Course getPublicCourseDetails(String courseId) {
        return courseRepository.findByIdAndStatus(courseId, CourseStatus.PUBLISHED);
    }

    @Override
    public List<Course> getUserCourses(String id) {
        return List.of();
    }

    @Override
    public Course getCourse(String courseId) {
        return courseRepository.findById(courseId).orElseThrow(() -> new CourseNotFoundException(courseId));
    }

    @Override
    @Transactional
    public Course createCourse(Course course) {

        course.setStatus(CourseStatus.DRAFT);
        course.setEnrollmentCount(0L);
        course.setTotalLessons(0);
        course.setCreatedAt(Instant.now());
        if (course.getPrice() != null && course.getPrice().compareTo(BigDecimal.ZERO) < 0) {
            throw new ValidationException("Price cannot be negative", "INVALID_PRICE");
        }
        try {
            Course savedCourse = courseRepository.save(course);
            log.info("Course created successfully with ID: {}", savedCourse.getId());
            return savedCourse;

        } catch (DataAccessException e) {
            log.error("Failed to create course: {}", e.getMessage());
            throw new DatabaseException("CREATE", "Course", e);
        }
    }

    @Override
    @Transactional
    public Course updateCourse(String courseId, Course course) {
        // Input validation
        if (courseId == null || courseId.trim().isEmpty()) {
            throw new ValidationException("Course ID cannot be null or empty", "COURSE_ID_REQUIRED");
        }

        if (course == null) {
            throw new ValidationException("Course data cannot be null", "COURSE_DATA_REQUIRED");
        }

        if (course.getPrice() != null && course.getPrice().compareTo(BigDecimal.ZERO) < 0) {
            throw new ValidationException("Price cannot be negative", "INVALID_PRICE");
        }

        try {
            // Fetch existing course first
            Course existingCourse = courseRepository.findById(courseId)
                    .orElseThrow(() -> new CourseNotFoundException(courseId));

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
            throw new DatabaseException("UPDATE", "Course", e);
        } catch (Exception e) {
            log.error("Unexpected error while updating course with ID {}: {}", courseId, e.getMessage());
            throw new DatabaseException("UPDATE", "Course", e);
        }
    }


    @Override
    @Transactional
    public List<VideoLesson> saveVideoLessonsAndUpdateCourse(String courseId, List<VideoLesson> lessons) {
        return courseRepository.findById(courseId)
                .map(course -> {
                    List<VideoLesson> savedLessons = videoLessonService.addVideoLessons(course.getId(), lessons);

                    // Update course details
                    course.setVideoLessonIds(savedLessons.stream()
                            .map(VideoLesson::getId)
                            .toList());

                    course.setTotalLessons(savedLessons.size());

                    // Null-safe duration handling
                    int totalDuration = savedLessons.stream()
                            .mapToInt(v -> v.getDurationMinutes() != null ? v.getDurationMinutes() : 0)
                            .sum();
                    course.setTotalDurationMinutes(totalDuration);

                    course.setUpdatedAt(Instant.now());
                    courseRepository.save(course);

                    return savedLessons;
                })
                .orElseThrow(() -> new CourseNotFoundException(courseId));
    }

    @Override
    @Transactional
    public void deleteCourse(String courseId) {
        try {
            courseRepository.deleteById(courseId);
            log.info("Course deleted successfully with ID: {}", courseId);
        } catch (DataAccessException e) {
            log.error("Failed to delete course with ID {}: {}", courseId, e.getMessage());
            throw new DatabaseException("DELETE", "Course", e);
        } catch (Exception e) {
            log.error("Unexpected error while deleting course with ID {}: {}", courseId, e.getMessage());
            throw new DatabaseException("DELETE", "Course", e);
        }
    }

    @Override
    @Transactional
    public List<Course> getAllCourses() {
        try {
            return courseRepository.findAll();
        } catch (DataAccessException e) {
            log.error("Failed to retrieve all courses: {}", e.getMessage());
            throw new DatabaseException("SELECT", "Course", e);
        } catch (Exception e) {
            log.error("Unexpected error while retrieving all courses: {}", e.getMessage());
            throw new DatabaseException("SELECT", "Course", e);
        }
    }

    @Override
    @Transactional(readOnly = true)
    public VideoLesson getVideoLesson(String courseId, String lessonId) {
        return videoLessonService.getVideoLesson(courseId, lessonId)
                .orElseThrow(() -> new LessonNotFoundException(lessonId, courseId));
    }

    @Override
    @Transactional
    public void deleteVideoLesson(String courseId, String lessonId) {
        videoLessonService.deleteVideoLesson(courseId, lessonId);
    }

    @Override
    public List<VideoLesson> getAllLessonsByCourseId(String courseId) {
        var lessons = videoLessonService.getAllLessonsByCourseId(courseId);
        if (lessons.isEmpty()) {
            throw new LessonNotFoundException("any", courseId);
        } else {
            return lessons;
        }
    }


    @Override
    @Transactional
    public VideoLesson updateVideoLesson(String courseId, String lessonId, VideoLesson lesson) {

        return videoLessonService.getLessonByCourseIdAndLessonId(courseId, lessonId).map(
                existing -> {
                    updateVideoLessonFields(existing, lesson);
                    return videoLessonService.updateVideoLesson(existing);
                }
        ).orElseThrow(() -> new LessonNotFoundException(lessonId, courseId));

    }

    @Override
    @Transactional
    public List<VideoLesson> getVideoLessonsWithFreePreview(String courseId) {
        var lessons = videoLessonService.getFreePreviewLessonsByCourseId(courseId);
        if (lessons.isEmpty()) {
            throw new LessonNotFoundException("free preview", courseId);
        }
        return lessons;
    }


    private void updateVideoLessonFields(VideoLesson existing, VideoLesson updated) {
        if (updated.getTitle() != null) {
            existing.setTitle(updated.getTitle());
        }
        if (updated.getYoutubeUrl() != null) {
            existing.setYoutubeUrl(updated.getYoutubeUrl());
        }
        if (updated.getOrderIndex() != null) {
            existing.setOrderIndex(updated.getOrderIndex());
        }
        if (updated.getDescription() != null) {
            existing.setDescription(updated.getDescription());
        }
        if (updated.getDurationMinutes() != null) {
            existing.setDurationMinutes(updated.getDurationMinutes());
        }
        if (updated.getIsFreePreview() != null) {
            existing.setIsFreePreview(updated.getIsFreePreview());
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
