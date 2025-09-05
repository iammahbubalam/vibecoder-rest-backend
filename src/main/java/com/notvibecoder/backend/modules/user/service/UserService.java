package com.notvibecoder.backend.modules.user.service;

import com.notvibecoder.backend.modules.user.dto.UserUpdateRequest;
import com.notvibecoder.backend.modules.user.entity.User;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

import java.util.List;

public interface UserService {
    boolean existsByEmail(String email);
    User updateProfile(String email, UserUpdateRequest updateRequest);
    User findByEmail(String email);
    User findById(String id);
    void addPurchasedCourse(String userId, String courseId);
    void removePurchasedCourse(String userId, String courseId);
    void changeUserRole(String userId, String newRole);
    void deleteUser(String userId);
    List<User> getAllUsers();
    Page<User> getAllUsers(Pageable pageable);
}
