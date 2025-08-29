package com.notvibecoder.backend.modules.courses.utils;

import com.notvibecoder.backend.modules.courses.dto.CourseDTO;
import com.notvibecoder.backend.modules.courses.entity.Course;
import org.springframework.stereotype.Component;

import java.util.ArrayList;

@Component
public class CourseConverter {

    public Course convertToEntity(CourseDTO dto) {
        if (dto == null) {
            return null;
        }

        return Course.builder()
                .title(dto.getTitle())
                .description(dto.getDescription())
                .shortDescription(dto.getShortDescription())
                .price(dto.getPrice())
                .thumbnailUrl(dto.getThumbnailUrl())
                .previewVideoUrl(dto.getPreviewVideoUrl())
                .status(dto.getStatus())
                .whatYouWillLearn(dto.getWhatYouWillLearn() != null ? dto.getWhatYouWillLearn() : new ArrayList<>())
                .requirements(dto.getRequirements() != null ? dto.getRequirements() : new ArrayList<>())
                .category(dto.getCategory())
                .tags(dto.getTags() != null ? dto.getTags() : new ArrayList<>())
                .totalDurationMinutes(dto.getTotalDurationMinutes())
                .build();
    }

    public CourseDTO convertToDto(Course entity) {
        if (entity == null) {
            return null;
        }

        return CourseDTO.builder()
                .title(entity.getTitle())
                .description(entity.getDescription())
                .shortDescription(entity.getShortDescription())
                .price(entity.getPrice())
                .thumbnailUrl(entity.getThumbnailUrl())
                .previewVideoUrl(entity.getPreviewVideoUrl())
                .status(entity.getStatus())
                .whatYouWillLearn(entity.getWhatYouWillLearn())
                .requirements(entity.getRequirements())
                .category(entity.getCategory())
                .tags(entity.getTags())
                .totalDurationMinutes(entity.getTotalDurationMinutes())
                .build();
    }
}