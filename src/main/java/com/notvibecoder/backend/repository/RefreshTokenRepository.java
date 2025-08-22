package com.notvibecoder.backend.repository;
import java.time.Instant;
import java.util.Optional;


import com.notvibecoder.backend.entity.RefreshToken;
import org.springframework.data.mongodb.repository.MongoRepository;
import com.notvibecoder.backend.entity.User;

public interface RefreshTokenRepository extends MongoRepository<RefreshToken, String> {
    Optional<RefreshToken> findByToken(String token);
    int deleteByUserId(String userId);
    void deleteByExpiryDateBefore(Instant date); // For cleanup
    @Modifying
    @Query("UPDATE RefreshToken rt SET rt.revoked = true WHERE rt.id = :tokenId")
    int revokeToken(@Param("tokenId") String tokenId);

    @Modifying
    @Query("UPDATE RefreshToken rt SET rt.revoked = true WHERE rt.userId = :userId AND rt.revoked = false")
    int revokeAllByUserId(@Param("userId") String userId);
}
