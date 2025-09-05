package com.notvibecoder.backend.core.exception.course;

import com.notvibecoder.backend.core.exception.BusinessException;

import lombok.Getter;

@Getter
public class LessonNotFoundException extends BusinessException {
    private final String lessonId;
    private final String courseId;

    public LessonNotFoundException(String lessonId, String courseId) {
        super(String.format("Lesson %s not found in course %s", lessonId, courseId), "LESSON_NOT_FOUND");
        this.lessonId = lessonId;
        this.courseId = courseId;
    }
}

