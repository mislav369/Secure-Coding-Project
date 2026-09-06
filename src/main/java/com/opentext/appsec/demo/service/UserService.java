package com.opentext.appsec.demo.service;


import org.springframework.stereotype.Service;

import com.opentext.appsec.demo.model.User;
import com.opentext.appsec.demo.repository.UserRepository;

import jakarta.persistence.EntityManager;
import jakarta.persistence.Query;

import java.util.List;

import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * User service with intentional security vulnerabilities.
 */
@Service
public class UserService {

    private final UserRepository userRepository;
    private final EntityManager entityManager;
    private final PasswordEncoder passwordEncoder;

    public UserService(
            UserRepository userRepository,
            EntityManager entityManager,
            PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.entityManager = entityManager;
        this.passwordEncoder = passwordEncoder;
    }




    public User findUserByUsername(String username) {

        String sql = "SELECT * FROM users WHERE username = :username";
        Query query = entityManager.createNativeQuery(sql, User.class);
        query.setParameter("username", username);
        List<User> results = query.getResultList();
        return results.isEmpty() ? null : results.get(0);
    }

    //public List<User> searchUsersVulnerable(String searchTerm) {
        //String sql = "SELECT * FROM users WHERE username LIKE '%" + searchTerm + "%'"
               // + " OR email LIKE '%" + searchTerm + "%'";
        //Query query = entityManager.createNativeQuery(sql, User.class);
        //return query.getResultList();
    //}

    /**
     * Authenticate user with weak password hashing.
     * Uses MD5 which is cryptographically broken.
     */
    public boolean authenticateUser(String username, String password) {
        User user = userRepository.findByUsername(username);

        return user != null
                && passwordEncoder.matches(password, user.getPassword());
    }

    /**
     * Create a new user.
     */
    public User createUser(User user) {
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        return userRepository.save(user);
    }

    public User updateUser(User user, String newPassword) {
        if (newPassword != null && !newPassword.isBlank()) {
            user.setPassword(passwordEncoder.encode(newPassword));
        }

        return userRepository.save(user);
    }

    /**
     * Get all users.
     */
    public List<User> getAllUsers() {
        return userRepository.findAll();
    }

    /**
     * Search users with SQL injection vulnerability.
     */
    public List<User> searchUsers(String searchTerm) {
        String sql = """
            SELECT * FROM users
            WHERE username LIKE :searchTerm
               OR email LIKE :searchTerm
            """;

        Query query = entityManager.createNativeQuery(sql, User.class);
        query.setParameter("searchTerm", "%" + searchTerm + "%");

        return query.getResultList();
    }


}
