package com.notvibecoder.backend.modules.courses.repository;

import com.notvibecoder.backend.modules.courses.entity.Course;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface CourseRepository extends MongoRepository<Course, String> {
}
