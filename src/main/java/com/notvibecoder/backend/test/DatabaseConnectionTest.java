package com.notvibecoder.backend.test;


import lombok.extern.slf4j.Slf4j;
import org.bson.Document;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.stereotype.Component;

import java.util.HashSet;
import java.util.Set;

@Component
@Slf4j
public class DatabaseConnectionTest implements ApplicationRunner {

    @Autowired
    private MongoTemplate mongoTemplate;
    // @Autowired
    // private UserRepository userRepository;
    @Override
    public void run(ApplicationArguments args) throws Exception {
        try {
//            log.info("🔗 Testing MongoDB connection...");
//            User user = User.builder()
//                    .email("bubhamnojrin7196@gmail.com")
//                    .name("Bubham Nojrin")
//                    .pictureUrl("https://example.com/profile.jpg")
//                    .provider(AuthProvider.google)
//                    .providerId("1234567890")
//                    .roles(Set.of(Role.STUDENT))
//                    .build();
//            userRepository.save(user);


            // Test database connection
            mongoTemplate.getDb().runCommand(new Document("ping", 1));
            log.info("✅ MongoDB connection successful!");
            log.info("Database name: {}", mongoTemplate.getDb().getName());

            // List collections
            Set<String> collections = mongoTemplate.getDb().listCollectionNames().into(new HashSet<>());
            log.info("Available collections: {}", collections);

        } catch (Exception e) {
            log.error("❌ MongoDB connection failed: {}", e.getMessage());
        }
    }
}