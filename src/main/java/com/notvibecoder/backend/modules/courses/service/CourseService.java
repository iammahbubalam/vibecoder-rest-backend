package com.notvibecoder.backend.modules.courses.service;

import com.notvibecoder.backend.modules.courses.entity.Course;
import com.notvibecoder.backend.modules.courses.entity.CourseStatus;
import com.notvibecoder.backend.modules.courses.entity.VideoLesson;

import java.util.List;


public interface CourseService {
    Course isCoursePublished(String courseId);

    void updateCourseStatus(String courseId, CourseStatus status);

    List<Course> getPublishedCourses();

    Course getPublicCourseDetails(String courseId);

    List<Course> getUserCourses(String id);

    Course getCourse(String courseId);

    Course createCourse(Course course);

    Course updateCourse(String courseId, Course course);

    void deleteCourse(String courseId);

    List<Course> getAllCourses();

    public List<VideoLesson> saveVideoLessonsAndUpdateCourse(String courseId, List<VideoLesson> lessons);

    VideoLesson getVideoLesson(String courseId, String lessonId);

    void deleteVideoLesson(String courseId, String lessonId);

    List<VideoLesson> getAllLessonsByCourseId(String courseId);

    VideoLesson updateVideoLesson(String courseId, String lessonId, VideoLesson lesson);

    List<VideoLesson> getVideoLessonsWithFreePreview(String courseId);

}
