
package com.notvibecoder.backend.modules.courses.service;

import org.springframework.stereotype.Service;
import java.util.List;
import java.util.Optional;

import com.notvibecoder.backend.modules.courses.entity.VideoLesson;
import com.notvibecoder.backend.modules.courses.repository.VideoLessonRepository;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;


@Slf4j
@Service
@RequiredArgsConstructor
public class VideoLessonServiceImpl implements VideoLessonService {

    private final VideoLessonRepository videoLessonRepository;


    @Override
    public List<VideoLesson> creatVideoLesson(String courseId , List<VideoLesson> lessons) {
        log.info("Creating {} video lessons for course: {}", lessons.size(), courseId);

        // Validate course ID
        if (courseId == null || courseId.trim().isEmpty()) {
            throw new IllegalArgumentException("Course ID cannot be null or empty");
        }

        // Validate lessons list
        if (lessons == null || lessons.isEmpty()) {
            throw new IllegalArgumentException("Lessons list cannot be null or empty");
        }

        // Process each lesson and assign sequential order indexes
        for (int i = 0; i < lessons.size(); i++) {
            VideoLesson lesson = lessons.get(i);
            lesson.setCourseId(courseId);

            // Assign sequential order index (1, 2, 3, ...)
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
}