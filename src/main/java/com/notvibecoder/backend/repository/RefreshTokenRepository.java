package com.notvibecoder.backend.repository;

import com.notvibecoder.backend.entity.RefreshToken;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.data.mongodb.repository.Query;
import org.springframework.data.mongodb.repository.Update;

import java.time.Instant;
import java.util.Optional;

public interface RefreshTokenRepository extends MongoRepository<RefreshToken, String> {
    Optional<RefreshToken> findByToken(String token);

    void deleteByUserId(String userId);

    void deleteByExpiryDateBefore(Instant date);

    @Query("{ '_id': ?0 }")
    @Update("{ '$set': { 'revoked': true } }")
    int revokeToken(String tokenId);

    @Query("{ 'userId': ?0, 'revoked': false }")
    @Update("{ '$set': { 'revoked': true } }")
    int revokeAllByUserId(String userId);
}
