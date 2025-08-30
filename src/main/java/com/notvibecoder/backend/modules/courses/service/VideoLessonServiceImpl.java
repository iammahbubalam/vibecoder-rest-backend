
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