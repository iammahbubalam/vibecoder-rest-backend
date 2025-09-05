package com.notvibecoder.backend.core.exception.course;

import com.notvibecoder.backend.core.exception.BusinessException;

import lombok.Getter;

@Getter
public class CourseNotFoundException extends BusinessException {
    private final String courseId;

    public CourseNotFoundException(String courseId) {
        super(String.format("Course not found with ID: %s", courseId), "COURSE_NOT_FOUND");
        this.courseId = courseId;
    }
}
