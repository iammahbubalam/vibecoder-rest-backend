package com.notvibecoder.backend.core.exception.course;

import com.notvibecoder.backend.core.exception.BusinessException;

import lombok.Getter;

@Getter
public class CourseNotPublishedException extends BusinessException {
    private final String courseId;

    public CourseNotPublishedException(String courseId) {
        super(String.format("Course %s is not published", courseId), "COURSE_NOT_PUBLISHED");
        this.courseId = courseId;
    }
}