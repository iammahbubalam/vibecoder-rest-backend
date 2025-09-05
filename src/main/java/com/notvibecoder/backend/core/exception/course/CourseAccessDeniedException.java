package com.notvibecoder.backend.core.exception.course;

import com.notvibecoder.backend.core.exception.BusinessException;

import lombok.Getter;

@Getter
public class CourseAccessDeniedException extends BusinessException {
    private final String courseId;
    private final String userId;

    public CourseAccessDeniedException(String courseId, String userId) {
        super(String.format("User %s does not have access to course %s", userId, courseId), "COURSE_ACCESS_DENIED");
        this.courseId = courseId;
        this.userId = userId;
    }
}