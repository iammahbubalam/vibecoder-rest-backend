package com.notvibecoder.backend.modules.system.service;

import com.notvibecoder.backend.config.properties.AppProperties;
import com.notvibecoder.backend.modules.user.entity.Role;
import com.notvibecoder.backend.modules.user.entity.User;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.Arrays;
import java.util.Set;

@Service
@RequiredArgsConstructor
@Slf4j
public class AdminService {

    private final AppProperties appProperties;

    /**
     * Checks if the given email is configured as an admin email.
     *
     * @param email the email to check
     * @return true if the email is an admin email, false otherwise
     */
    public boolean isAdminEmail(String email) {
        if (email == null || email.trim().isEmpty()) {
            log.debug("Email is null or empty, not admin");
            return false;
        }

        String[] adminEmails = appProperties.admin().emails();
        log.debug("Checking email '{}' against admin emails: {}", email, String.join(", ", adminEmails));

        boolean isAdmin = Arrays.stream(adminEmails)
                .anyMatch(adminEmail -> adminEmail.equalsIgnoreCase(email.trim()));

        if (isAdmin) {
            log.info("Admin email detected: {}", email);
        } else {
            log.debug("Email '{}' is not in admin list", email);
        }

        return isAdmin;
    }

    /**
     * Determines the appropriate roles for a user based on their email.
     * Admin emails get ADMIN role, others get USER role.
     *
     * @param email the user's email
     * @return set of roles for the user
     */
    public Set<Role> determineUserRoles(String email) {
        if (isAdminEmail(email)) {
            log.info("Granting ADMIN role to user: {}", email);
            return Set.of(Role.ADMIN, Role.USER); // Admin users also have USER role
        } else {
            return Set.of(Role.USER);
        }
    }

    /**
     * Upgrades an existing user to admin if their email is in the admin list.
     *
     * @param user the user to potentially upgrade
     * @return true if the user was upgraded, false otherwise
     */
    public boolean upgradeToAdminIfEligible(User user) {
        if (user == null || user.getEmail() == null) {
            return false;
        }

        if (isAdminEmail(user.getEmail()) && !user.getRoles().contains(Role.ADMIN)) {
            log.info("Upgrading user to admin: {}", user.getEmail());
            user.getRoles().add(Role.ADMIN);
            return true;
        }

        return false;
    }

    /**
     * Gets all configured admin emails.
     *
     * @return array of admin emails
     */
    public String[] getAdminEmails() {
        return appProperties.admin().emails();
    }
}
