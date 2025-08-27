package com.notvibecoder.backend.modules.auth.repository;

import com.notvibecoder.backend.modules.auth.entity.RefreshToken;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.data.mongodb.repository.Query;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.List;
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

    List<RefreshToken> findAllByUserId(String userId);

}