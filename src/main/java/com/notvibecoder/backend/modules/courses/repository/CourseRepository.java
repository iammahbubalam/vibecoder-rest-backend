package com.notvibecoder.backend.modules.courses.repository;

import com.notvibecoder.backend.modules.courses.entity.Course;
import com.notvibecoder.backend.modules.courses.entity.CourseStatus;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.data.mongodb.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface CourseRepository extends MongoRepository<Course, String> {

    @Query("{ '_id': ?0, 'status': ?1 }")
    Course findByIdAndStatus(String courseId, CourseStatus published);

    @Query("{ 'status': ?0 }")
    List<Course> findByStatus(CourseStatus published);
}
