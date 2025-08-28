package com.notvibecoder.backend.modules.learning.entity;

import jakarta.validation.constraints.NotBlank;
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
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.data.mongodb.core.mapping.Field;

import java.time.Instant;
import java.util.Map;
import java.util.Set;

@Document(collection = "learning_progress")
@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
@CompoundIndexes({
        @CompoundIndex(name = "user_course_unique_idx",
                def = "{'userId': 1, 'courseId': 1}",
                unique = true),
        @CompoundIndex(name = "user_status_updated_idx",
                def = "{'userId': 1, 'completionStatus': 1, 'lastUpdated': -1}"),
        @CompoundIndex(name = "course_progress_idx",
                def = "{'courseId': 1, 'progressPercentage': -1}"),
        @CompoundIndex(name = "purchase_progress_idx",
                def = "{'purchaseId': 1}")
})
public class LearningProgress {
    
    @Id
    private String id;

    @Indexed
    @NotBlank(message = "User ID is required")
    @Field("user_id")
    private String userId;

    @Indexed
    @NotBlank(message = "Course ID is required")
    @Field("course_id")
    private String courseId;

    @Indexed
    @NotBlank(message = "Purchase ID is required")
    @Field("purchase_id")
    private String purchaseId;

    @Builder.Default
    @Field("completed_lessons")
    private Set<Integer> completedLessons = Set.of();

    @Builder.Default
    @Field("lesson_watch_time")
    private Map<Integer, Integer> lessonWatchTime = Map.of();

    @Indexed
    @Builder.Default
    @Field("progress_percentage")
    private Double progressPercentage = 0.0;

    @Field("last_watched_lesson")
    private Integer lastWatchedLesson;

    @Indexed
    @Field("completion_status")
    private CompletionStatus completionStatus;

    @CreatedDate
    @Field("started_at")
    private Instant startedAt;

    @Indexed
    @LastModifiedDate
    @Field("last_updated")
    private Instant lastUpdated;

    @Field("completed_at")
    private Instant completedAt;

    @org.springframework.data.annotation.Version
    @Field("version")
    private Long version;
}