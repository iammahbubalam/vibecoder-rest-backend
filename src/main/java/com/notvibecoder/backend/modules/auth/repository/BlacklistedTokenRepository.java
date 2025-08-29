package com.notvibecoder.backend.modules.auth.repository;

import com.notvibecoder.backend.modules.auth.entity.BlacklistedToken;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

import java.time.Instant;


@Repository
public interface BlacklistedTokenRepository extends MongoRepository<BlacklistedToken, String> {

    boolean existsByJwtId(String jwtId);

    void deleteByUserId(String userId);

    long deleteByExpiresAtBefore(Instant now);

}
