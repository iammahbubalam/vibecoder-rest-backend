package com.notvibecoder.backend.modules.courses.repository;
import java.util.List;
import java.util.Optional;

import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.data.mongodb.repository.Query;
import com.notvibecoder.backend.modules.courses.entity.VideoLesson;

public interface VideoLessonRepository extends MongoRepository<VideoLesson, String> {

    List<VideoLesson> findByCourseId(String courseId);
    Optional<VideoLesson> findByCourseIdAndOrderIndex(String courseId, Integer orderIndex);
    List<VideoLesson> findByCourseIdOrderByOrderIndexAsc(String courseId);

    List<VideoLesson> findAllLessonsByCourseId(String courseId);
    @Query("{ 'courseId': ?0, 'isFreePreview': true }")
    List<VideoLesson> findFreePreviewLessonsByCourseId(String courseId);
}