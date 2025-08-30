package com.notvibecoder.backend.modules.courses.entity;

import jakarta.validation.constraints.DecimalMin;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.mongodb.core.index.CompoundIndex;
import org.springframework.data.mongodb.core.index.CompoundIndexes;
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.index.TextIndexed;
import org.springframework.data.mongodb.core.mapping.DBRef;
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.data.mongodb.core.mapping.Field;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.List;

@Document(collection = "courses")
@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
@CompoundIndexes({
        @CompoundIndex(name = "status_created_idx",
                def = "{'status': 1, 'createdAt': -1}"),
        @CompoundIndex(name = "status_price_idx",
                def = "{'status': 1, 'price': 1}"),
        @CompoundIndex(name = "status_enrollment_idx",
                def = "{'status': 1, 'enrollmentCount': -1}"),
        @CompoundIndex(name = "instructor_status_idx",
                def = "{'instructorName': 1, 'status': 1}"),
        @CompoundIndex(name = "price_range_idx",
                def = "{'price': 1, 'status': 1}")
})
public class Course {

    @Id
    private String id;

    @TextIndexed(weight = 3)
    @NotBlank(message = "Title is required")
    @Size(min = 5, max = 200)
    @Field("title")
    private String title;

    @TextIndexed(weight = 2)
    @NotBlank(message = "Description is required")
    @Size(min = 20, max = 1000)
    @Field("description")
    private String description;

    @TextIndexed(weight = 1)
    @Field("short_description")
    private String shortDescription;

    @Indexed
    @NotBlank(message = "Instructor name is required")
    @Field("instructor_name")
    private String instructorName;

    @Indexed
    @NotNull(message = "Price is required")
    @DecimalMin(value = "0.0")
    @Field("price")
    private BigDecimal price;

    @Field("thumbnail_url")
    private String thumbnailUrl;

    @Field("preview_video_url")
    private String previewVideoUrl;

    @Indexed
    @NotNull(message = "Status is required")
    @Field("status")
    private CourseStatus status;


    // Keep IDs for performance queries when you don't need full objects
    @Indexed
    @Field("video_lesson_ids")
    private List<String> videoLessonIds;

    @Field("what_you_will_learn")
    private List<String> whatYouWillLearn;

    @Field("requirements")
    private List<String> requirements;

    @Indexed
    @Builder.Default
    @Field("total_lessons")
    private Integer totalLessons = 0;

    @Field("total_duration_minutes")
    private Integer totalDurationMinutes;

    @Indexed
    @Builder.Default
    @Field("enrollment_count")
    private Long enrollmentCount = 0L;

    @Field("category")
    private String category;

    @Indexed
    @Field("tags")
    private List<String> tags;

    @Indexed
    @CreatedDate
    @Field("created_at")
    private Instant createdAt;

    @LastModifiedDate
    @Field("updated_at")
    private Instant updatedAt;

    @org.springframework.data.annotation.Version
    @Field("version")
    private Long version;
}