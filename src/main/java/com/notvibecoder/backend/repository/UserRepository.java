package com.notvibecoder.backend.repository;



import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.data.mongodb.repository.Query;
import org.springframework.stereotype.Repository;

import com.notvibecoder.backend.entity.AuthProvider;
import com.notvibecoder.backend.entity.Role;
import com.notvibecoder.backend.entity.User;

import java.time.Instant;
import java.util.Optional;
import java.util.Set;

@Repository
public interface UserRepository extends MongoRepository<User, String> {
    
    Optional<User> findByEmail(String email);
    
    Optional<User> findByProviderAndProviderId(AuthProvider provider, String providerId);
    
    @Query("{ 'email': ?0, 'enabled': true }")
    Optional<User> findActiveUserByEmail(String email);
    
    @Query("{ 'roles': { $in: ?0 }, 'enabled': true }")
    Page<User> findActiveUsersByRoles(Set<Role> roles, Pageable pageable);
    
    @Query("{ 'createdAt': { $gte: ?0, $lte: ?1 } }")
    Page<User> findUsersByDateRange(Instant startDate, Instant endDate, Pageable pageable);
    
    boolean existsByEmailAndProvider(String email, AuthProvider provider);
    
    long countByRolesAndEnabled(Set<Role> roles, boolean enabled);
}