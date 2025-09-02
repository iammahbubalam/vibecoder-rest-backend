package com.notvibecoder.backend.modules.courses.service;

import com.notvibecoder.backend.modules.courses.entity.VideoLesson;
import com.notvibecoder.backend.modules.courses.repository.VideoLessonRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;


@Slf4j
@Service
@RequiredArgsConstructor
public class VideoLessonServiceImpl implements VideoLessonService {

    private final VideoLessonRepository videoLessonRepository;


    @Override
    @Transactional
    public List<VideoLesson> createVideoLesson(String courseId, List<VideoLesson> lessons) {
        log.info("Creating {} video lessons for course: {}", lessons.size(), courseId);

        // Validate course ID
        if (courseId == null || courseId.trim().isEmpty()) {
            throw new IllegalArgumentException("Course ID cannot be null or empty");
        }

        // Validate lessons list
        if (lessons.isEmpty()) {
            throw new IllegalArgumentException("Lessons list cannot be null or empty");
        }

        // Process each lesson and assign sequential order indexes
        for (int i = 0; i < lessons.size(); i++) {
            VideoLesson lesson = lessons.get(i);
            lesson.setCourseId(courseId);
            lesson.setOrderIndex(i + 1);

        }
        return videoLessonRepository.saveAll(lessons);
    }

    @Override
    public List<VideoLesson> getAllLessonsByCourseId(String courseId) {
        return videoLessonRepository.findAllLessonsByCourseId(courseId);
    }

    @Override
    public Optional<VideoLesson> getLessonByCourseIdAndOrderIndex(String courseId, Integer orderIndex) {
        return videoLessonRepository.findByCourseIdAndOrderIndex(courseId, orderIndex);
    }

    @Override
    public List<VideoLesson> getFreePreviewLessonsByCourseId(String courseId) {
        return videoLessonRepository.findFreePreviewLessonsByCourseId(courseId);
    }

    @Override
    public VideoLesson getVideoLesson(String courseId, String lessonId) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'getVideoLesson'");
    }

    @Override
    public void deleteVideoLesson(String courseId, String lessonId) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'deleteVideoLesson'");
    }

    @Override
    public VideoLesson addVideoLesson(String courseId, VideoLesson lesson) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'addVideoLesson'");
    }

    @Override
    public VideoLesson updateVideoLesson(String courseId, String lessonId, VideoLesson lesson) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'updateVideoLesson'");
    }

    @Override
    public List<VideoLesson> getVideoLessonsWithFreePreview(String courseId, String lessonId) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'getVideoLessonsWithFreePreview'");
    }
}