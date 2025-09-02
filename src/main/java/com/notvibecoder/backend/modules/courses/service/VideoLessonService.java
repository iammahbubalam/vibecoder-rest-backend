

package com.notvibecoder.backend.modules.courses.service;

import java.util.List;
import java.util.Optional;
import com.notvibecoder.backend.modules.courses.entity.VideoLesson;

public interface VideoLessonService {

    List<VideoLesson> createVideoLesson(String courseId,List<VideoLesson> lessons);
    List<VideoLesson> getAllLessonsByCourseId(String courseId);
    Optional<VideoLesson> getLessonByCourseIdAndOrderIndex(String courseId, Integer orderIndex);
    List<VideoLesson> getFreePreviewLessonsByCourseId(String courseId);
    public VideoLesson getVideoLesson(String courseId, String lessonId);
    public void deleteVideoLesson(String courseId, String lessonId);
    public VideoLesson addVideoLesson(String courseId, VideoLesson lesson);
    public VideoLesson updateVideoLesson(String courseId, String lessonId, VideoLesson lesson);
    public List<VideoLesson> getVideoLessonsWithFreePreview(String courseId, String lessonId);
}