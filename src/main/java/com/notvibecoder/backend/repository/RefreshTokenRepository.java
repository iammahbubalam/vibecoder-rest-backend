package com.notvibecoder.backend.repository;

import com.notvibecoder.backend.entity.RefreshToken;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.data.mongodb.repository.Query;
import org.springframework.data.mongodb.repository.Update;

import java.time.Instant;
import java.util.Optional;

public interface RefreshTokenRepository extends MongoRepository<RefreshToken, String> {
    
    Optional<RefreshToken> findByToken(String token);
    
    Optional<RefreshToken> findByUserId(String userId); // ✅ Single session: one token per user
    
    void deleteByUserId(String userId);
    
    void deleteByExpiryDateBefore(Instant date);
    
    @Query("{ '_id': ?0 }")
    @Update("{ '$set': { 'isRevoked': true } }")
    int revokeToken(String tokenId);
    
    @Query("{ 'userId': ?0, 'isRevoked': false }")
    @Update("{ '$set': { 'isRevoked': true } }")
    int revokeAllByUserId(String userId);
    
    // ✅ Single session queries
    boolean existsByUserId(String userId);
    
    @Query("{ 'userId': ?0, 'isRevoked': false }")
    Optional<RefreshToken> findActiveTokenByUserId(String userId);
}