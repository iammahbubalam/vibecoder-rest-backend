package com.notvibecoder.backend.modules.courses.dto;

import com.notvibecoder.backend.modules.courses.entity.CourseStatus;
import jakarta.validation.constraints.DecimalMin;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.math.BigDecimal;
import java.util.List;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class CourseDTO {

    @NotBlank(message = "Title is required")
    @Size(min = 5, max = 200, message = "Title must be between 5 and 200 characters")
    private String title;

    @NotBlank(message = "Description is required")
    @Size(min = 20, max = 1000, message = "Description must be between 20 and 1000 characters")
    private String description;

    @Size(max = 500, message = "Short description cannot exceed 500 characters")
    private String shortDescription;

    @NotNull(message = "Price is required")
    @DecimalMin(value = "0.0", message = "Price must be non-negative")
    private BigDecimal price;

    private String thumbnailUrl;

    private String previewVideoUrl;

    @NotNull(message = "Status is required")
    private CourseStatus status;

    private List<String> whatYouWillLearn;

    private List<String> requirements;

    @Size(max = 100, message = "Category name too long")
    private String category;

    private List<String> tags;

    private Integer totalDurationMinutes;
}