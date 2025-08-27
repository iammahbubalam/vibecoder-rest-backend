package com.notvibecoder.backend.modules.auth.repository;

import com.notvibecoder.backend.modules.auth.entity.BlacklistedToken;

import java.time.Instant;

import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;


@Repository
public interface BlacklistedTokenRepository extends MongoRepository<BlacklistedToken, String> {

    boolean existsByJwtId(String jwtId);

    void deleteByUserId(String userId);

    long deleteByExpiresAtBefore(Instant now);

}
