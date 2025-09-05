package com.notvibecoder.backend.core.exception.order;

import com.notvibecoder.backend.core.exception.BusinessException;

import lombok.Getter;

@Getter
public class DuplicateTransactionException extends BusinessException {
    private final String transactionId;

    public DuplicateTransactionException(String transactionId) {
        super(String.format("Transaction ID %s already exists", transactionId), "DUPLICATE_TRANSACTION");
        this.transactionId = transactionId;
    }
}
