

package com.notvibecoder.backend.modules.courses.service;

import java.util.List;
import java.util.Optional;
import com.notvibecoder.backend.modules.courses.entity.VideoLesson;

public interface VideoLessonService {

    List<VideoLesson> creatVideoLesson(String courseId,List<VideoLesson> lessons);
    List<VideoLesson> getAllLessonsByCourseId(String courseId);
    Optional<VideoLesson> getLessonByCourseIdAndOrderIndex(String courseId, Integer orderIndex);
    List<VideoLesson> getFreePreviewLessonsByCourseId(String courseId);
}