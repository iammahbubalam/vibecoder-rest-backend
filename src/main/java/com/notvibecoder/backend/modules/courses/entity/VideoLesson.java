package com.notvibecoder.backend.modules.courses.entity;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.Field;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class VideoLesson {

    @NotBlank(message = "Title is required")
    @Field("title")
    private String title;

    @Indexed
    @NotBlank(message = "Course ID is required")
    @Field("course_id")
    private String courseId;

    @NotBlank(message = "YouTube URL is required")
    @Field("youtube_url")
    private String youtubeUrl;

    @NotNull(message = "Order is required")
    @Field("order_index")
    private Integer orderIndex;

    @Field("description")
    private String description;

    @Field("duration_minutes")
    private Integer durationMinutes;

    @Builder.Default
    @Field("is_free_preview")
    private Boolean isFreePreview = false;
}