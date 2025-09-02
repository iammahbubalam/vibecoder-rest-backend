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
    public Optional<VideoLesson> getVideoLesson(String courseId, String lessonId) {

        return videoLessonRepository.findByCourseIdAndLessonId(courseId, lessonId);
    }

    @Override
    public void deleteVideoLesson(String courseId, String lessonId) {
        videoLessonRepository.deleteVideoLesson(courseId, lessonId);
    }

    @Override
    @Transactional
    public List<VideoLesson> addVideoLessons(String courseId, List<VideoLesson> newLessons) {
        log.info("Adding {} video lessons to course: {}", newLessons.size(), courseId);

        if (courseId == null || courseId.trim().isEmpty()) {
            throw new IllegalArgumentException("Course ID cannot be null or empty");
        }
        if (newLessons == null || newLessons.isEmpty()) {
            throw new IllegalArgumentException("Lessons list cannot be null or empty");
        }

        List<VideoLesson> existingLessons = videoLessonRepository.findAllLessonsByCourseId(courseId);
        int maxOrderIndex = existingLessons.stream()
                .mapToInt(VideoLesson::getOrderIndex)
                .max()
                .orElse(0);

        for (int i = 0; i < newLessons.size(); i++) {
            VideoLesson lesson = newLessons.get(i);
            lesson.setCourseId(courseId);
            lesson.setOrderIndex(maxOrderIndex + i + 1);
        }

        existingLessons.addAll(newLessons);
        return videoLessonRepository.saveAll(existingLessons);
    }
    @Override
    @Transactional
    public VideoLesson updateVideoLesson( VideoLesson lesson) {
        return videoLessonRepository.save(lesson);
    }

    @Override
    @Transactional(readOnly = true)
    public Optional<VideoLesson> getLessonByCourseIdAndLessonId(String courseId, String lessonId) {
        var lessonOpt = videoLessonRepository.findByCourseIdAndLessonId(courseId, lessonId);
        return lessonOpt;
    }


}