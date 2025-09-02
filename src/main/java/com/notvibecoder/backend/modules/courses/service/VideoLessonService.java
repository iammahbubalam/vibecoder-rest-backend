package com.notvibecoder.backend.modules.courses.service;

import com.notvibecoder.backend.modules.courses.entity.VideoLesson;

import java.util.List;
import java.util.Optional;

public interface VideoLessonService {

    List<VideoLesson> createVideoLesson(String courseId, List<VideoLesson> lessons);

    List<VideoLesson> getAllLessonsByCourseId(String courseId);

    Optional<VideoLesson> getLessonByCourseIdAndOrderIndex(String courseId, Integer orderIndex);

    List<VideoLesson> getFreePreviewLessonsByCourseId(String courseId);

    VideoLesson getVideoLesson(String courseId, String lessonId);

    void deleteVideoLesson(String courseId, String lessonId);

    VideoLesson addVideoLesson(String courseId, VideoLesson lesson);

    VideoLesson updateVideoLesson(String courseId, String lessonId, VideoLesson lesson);

    List<VideoLesson> getVideoLessonsWithFreePreview(String courseId, String lessonId);
}