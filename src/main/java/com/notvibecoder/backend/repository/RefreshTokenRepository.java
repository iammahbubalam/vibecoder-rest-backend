package com.notvibecoder.backend.repository;

import com.notvibecoder.backend.entity.RefreshToken;  // ✅ CORRECT IMPORT
import org.springframework.data.mongodb.repository.MongoRepository;
// Removed incompatible import for MongoDB repositories
import org.springframework.data.mongodb.repository.Query;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.Optional;

@Repository
public interface RefreshTokenRepository extends MongoRepository<RefreshToken, String> {
    
    Optional<RefreshToken> findByToken(String token);
    
    @Query("{ 'userId': ?0, 'isRevoked': false }")
    Optional<RefreshToken> findActiveTokenByUserId(String userId);

    // Use naming convention for delete operation
    void deleteByUserIdAndIsRevoked(String userId, boolean isRevoked);
    
    void deleteByExpiryDateBefore(Instant date);
    
    @Query("{ 'userId': ?0, 'isRevoked': false, 'expiryDate': { $gt: ?1 } }")
    boolean hasActiveTokens(String userId, Instant currentTime);
    
    @Query("{ 'ipAddress': ?0, 'createdAt': { $gte: ?1 } }")
    long countByIpAddressAndCreatedAtAfter(String ipAddress, Instant after);
    
    // ✅ ADDED - Missing method used in service
    boolean existsByUserId(String userId);
}