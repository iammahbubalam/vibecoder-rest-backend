package com.notvibecoder.backend.modules.courses.entity;

import jakarta.validation.constraints.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.annotation.Version;
import org.springframework.data.mongodb.core.index.CompoundIndex;
import org.springframework.data.mongodb.core.index.CompoundIndexes;
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.data.mongodb.core.mapping.Field;

import java.time.Instant;

/**
 * Video Lesson Entity - Represents individual video lessons within a course
 * 
 * Industry-grade features:
 * - Proper MongoDB document with optimized indexes
 * - Comprehensive validation with custom messages
 * - Audit trail with creation and modification timestamps
 * - Optimistic locking with version control
 * - Compound indexes for query performance
 * - Builder pattern for immutable object creation
 * - Proper field mapping for MongoDB storage optimization
 */
@Document(collection = "video_lessons")
@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
@CompoundIndexes({
        @CompoundIndex(
                name = "course_order_unique_idx", 
                def = "{'courseId': 1, 'orderIndex': 1}",
                unique = true,
                background = true
        ),
        @CompoundIndex(
                name = "course_created_idx", 
                def = "{'courseId': 1, 'createdAt': -1}",
                background = true
        ),
        @CompoundIndex(
                name = "course_preview_idx", 
                def = "{'courseId': 1, 'isFreePreview': 1}",
                background = true
        ),
        @CompoundIndex(
                name = "course_duration_idx", 
                def = "{'courseId': 1, 'durationMinutes': -1}",
                background = true
        )
})
public class VideoLesson {


    @Id
    private String id;


    @NotBlank(message = "Video lesson title is required and cannot be blank")
    @Size(min = 3, max = 200, message = "Title must be between 3 and 200 characters")
    @Field("title")
    private String title;


    @Indexed(background = true)
    @NotBlank(message = "Course ID is required - video lesson must belong to a course")
    @Pattern(regexp = "^[a-zA-Z0-9]{1,50}$", message = "Course ID must be alphanumeric and max 50 characters")
    @Field("course_id")
    private String courseId;

    @NotBlank(message = "YouTube URL is required")
    @Field("youtube_url")
    private String youtubeUrl;

    @NotNull(message = "Order index is required for lesson sequencing")
    @Min(value = 1, message = "Order index must be positive (starting from 1)")
    @Max(value = 9999, message = "Order index cannot exceed 9999")
    @Field("order_index")
    private Integer orderIndex;


    @Size(max = 2000, message = "Description cannot exceed 2000 characters")
    @Field("description")
    private String description;

    @Min(value = 1, message = "Duration must be at least 1 minute if specified")
    @Max(value = 600, message = "Duration cannot exceed 600 minutes (10 hours)")
    @Field("duration_minutes")
    private Integer durationMinutes;


    @Indexed(background = true)
    @Builder.Default
    @Field("is_free_preview")
    private Boolean isFreePreview = false;


    @CreatedDate
    @Field("created_at")
    private Instant createdAt;

  
    @LastModifiedDate
    @Field("updated_at")
    private Instant updatedAt;


    @Version
    @Field("version")
    private Long version;


    public boolean isPreviewLesson() {
        return Boolean.TRUE.equals(this.isFreePreview);
    }


    public boolean hasDuration() {
        return this.durationMinutes != null && this.durationMinutes > 0;
    }

    public String getYouTubeVideoId() {
        if (youtubeUrl == null) return null;

        String regex = "(?<=watch\\?v=|/videos/|embed\\/|youtu.be\\/|\\/v\\/|\\/e\\/|watch\\?v%3D|watch\\?feature=player_embedded&v=|%2Fvideos%2F|embed%2F|youtu.be%2F|%2Fv%2F)[^#\\&\\?\\n]*";
        java.util.regex.Pattern pattern = java.util.regex.Pattern.compile(regex);
        java.util.regex.Matcher matcher = pattern.matcher(youtubeUrl);
        
        return matcher.find() ? matcher.group() : null;
    }


    public String getFormattedDuration() {
        if (!hasDuration()) return "Duration not specified";
        
        int hours = durationMinutes / 60;
        int minutes = durationMinutes % 60;
        
        if (hours > 0) {
            return minutes > 0 ? String.format("%dh %dm", hours, minutes) : String.format("%dh", hours);
        }
        return String.format("%dm", minutes);
    }
}