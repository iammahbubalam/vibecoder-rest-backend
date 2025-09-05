package com.notvibecoder.backend.modules.user.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class CourseRequest {

    @NotBlank(message = "Course ID is required")
    private String courseId;
}
