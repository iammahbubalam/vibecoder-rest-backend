package com.notvibecoder.backend.modules.courses.service;

import com.notvibecoder.backend.modules.courses.entity.Course;
import com.notvibecoder.backend.modules.courses.entity.VideoLesson;

import java.util.List;


public interface CourseService {

    List<Course> getPublishedCourses();

    Course getPublicCourseDetails(String courseId);

    List<Course> getUserCourses(String id);

    Course getCourseWithContent(String courseId);

    Course createCourse(Course course);

    Course updateCourse(String courseId, Course course);

    void deleteCourse(String courseId);

    List<Course> getAllCourses();

    List<VideoLesson> createVideoLesson(String courseId, List<VideoLesson> lesson);

    VideoLesson getVideoLesson(String courseId, String lessonId);

    void deleteVideoLesson(String courseId, String lessonId);

    VideoLesson addVideoLesson(String courseId, VideoLesson lesson);

    VideoLesson updateVideoLesson(String courseId, String lessonId, VideoLesson lesson);

    List<VideoLesson> getVideoLessonsWithFreePreview(String courseId);

}
