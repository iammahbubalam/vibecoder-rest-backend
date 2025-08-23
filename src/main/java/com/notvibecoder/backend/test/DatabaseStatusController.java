package com.notvibecoder.backend.test;

import org.bson.Document;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/db")
public class DatabaseStatusController {

    @Autowired
    private MongoTemplate mongoTemplate;

    @GetMapping("/status")
    public ResponseEntity<Map<String, Object>> getDatabaseStatus() {
        Map<String, Object> status = new HashMap<>();
        try {
            mongoTemplate.getDb().runCommand(new Document("ping", 1));
            status.put("connected", true);
            status.put("database", mongoTemplate.getDb().getName());
            status.put("collections", mongoTemplate.getDb().listCollectionNames().into(new ArrayList<>()));
            return ResponseEntity.ok(status);
        } catch (Exception e) {
            status.put("connected", false);
            status.put("error", e.getMessage());
            return ResponseEntity.status(500).body(status);
        }
    }
}