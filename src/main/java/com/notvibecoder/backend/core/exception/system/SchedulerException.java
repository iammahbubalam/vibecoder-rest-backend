package com.notvibecoder.backend.core.exception.system;

import com.notvibecoder.backend.core.exception.BusinessException;

import lombok.Getter;

@Getter
public class SchedulerException extends BusinessException {
    private final String jobName;

    public SchedulerException(String jobName, String message) {
        super(String.format("Scheduled job %s failed: %s", jobName, message), "SCHEDULER_ERROR");
        this.jobName = jobName;
    }

    public SchedulerException(String jobName, Throwable cause) {
        super(String.format("Scheduled job %s failed", jobName), "SCHEDULER_ERROR", cause);
        this.jobName = jobName;
    }
}