package com.notvibecoder.backend.modules.courses.repository;

import com.notvibecoder.backend.modules.courses.entity.VideoLesson;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.data.mongodb.repository.Query;

import java.util.List;
import java.util.Optional;

public interface VideoLessonRepository extends MongoRepository<VideoLesson, String> {

    List<VideoLesson> findByCourseId(String courseId);

    Optional<VideoLesson> findByCourseIdAndOrderIndex(String courseId, Integer orderIndex);

    List<VideoLesson> findByCourseIdOrderByOrderIndexAsc(String courseId);

    @Query("{ 'courseId': ?0 }")
    List<VideoLesson> findAllLessonsByCourseId(String courseId);

    @Query("{ 'courseId': ?0, 'isFreePreview': true }")
    List<VideoLesson> findFreePreviewLessonsByCourseId(String courseId);

    @Query("{ 'courseId': ?0, '_id': ?1 }")
    Optional<VideoLesson> findByCourseIdAndLessonId(String courseId, String lessonId);

    @Query(value = "{ 'courseId': ?0, '_id': ?1 }", delete = true)
    void deleteVideoLesson(String courseId, String lessonId);

}