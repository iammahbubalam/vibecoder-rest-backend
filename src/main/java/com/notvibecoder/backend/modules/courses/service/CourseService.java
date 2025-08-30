package com.notvibecoder.backend.modules.courses.service;

import com.notvibecoder.backend.modules.courses.entity.Course;
import com.notvibecoder.backend.modules.courses.entity.VideoLesson;

import java.util.List;


public interface CourseService {

    public List<Course> getPublishedCourses();

    public Course getPublicCourseDetails(String courseId);

    public List<Course> getUserCourses(String id);

    public Course getCourseWithContent(String courseId);

    public Course createCourse(Course course);

    public Course updateCourse(String courseId, Course course);
    public List<VideoLesson> createVideoLesson(String courseId, List<VideoLesson> lesson);

    public void deleteCourse(String courseId);

    public List<Course> getAllCourses();

}
