package com.notvibecoder.backend.repository;

import com.notvibecoder.backend.entity.BlacklistedToken;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;


@Repository
public interface BlacklistedTokenRepository extends MongoRepository<BlacklistedToken, String> {
    
    boolean existsByJwtId(String jwtId);
    
    void deleteByUserId(String userId);
    
}
