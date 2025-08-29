package com.notvibecoder.backend.modules.courses.service;

import com.notvibecoder.backend.core.exception.CourseCreationException;
import com.notvibecoder.backend.core.exception.ValidationException;
import com.notvibecoder.backend.modules.courses.entity.Course;
import com.notvibecoder.backend.modules.courses.entity.CourseStatus;
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
    public Course updateCourse(String courseId, Course course) {
        return null;
    }

    @Override
    public void deleteCourse(String courseId) {

    }

    @Override
    public List<Course> getAllCourses() {
        return List.of();
    }

}
