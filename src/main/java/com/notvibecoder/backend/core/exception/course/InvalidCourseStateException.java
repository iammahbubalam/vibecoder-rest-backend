package com.notvibecoder.backend.core.exception.course;

import com.notvibecoder.backend.core.exception.BusinessException;

import lombok.Getter;

@Getter
public class InvalidCourseStateException extends BusinessException {
    private final String courseId;
    private final String currentState;
    private final String requiredState;

    public InvalidCourseStateException(String courseId, String currentState, String requiredState) {
        super(String.format("Course %s is in state %s, but %s is required", courseId, currentState, requiredState), 
              "INVALID_COURSE_STATE");
        this.courseId = courseId;
        this.currentState = currentState;
        this.requiredState = requiredState;
    }
}
