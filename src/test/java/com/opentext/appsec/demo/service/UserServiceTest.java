package com.opentext.appsec.demo.service;

import com.opentext.appsec.demo.model.User;
import com.opentext.appsec.demo.repository.UserRepository;
import jakarta.persistence.EntityManager;
import jakarta.persistence.Query;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class UserServiceTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private EntityManager entityManager;

    @Mock
    private PasswordEncoder passwordEncoder;

    @InjectMocks
    private UserService userService;

    @Test
    void shouldAuthenticateValidUser() {
        User user = new User(
                "admin",
                "encodedPassword",
                "admin@example.com",
                "ADMIN");

        when(userRepository.findByUsername("admin"))
                .thenReturn(user);

        when(passwordEncoder.matches(
                "admin123",
                "encodedPassword"))
                .thenReturn(true);

        assertTrue(
                userService.authenticateUser(
                        "admin",
                        "admin123"));
    }

    @Test
    void shouldRejectWrongPassword() {
        User user = new User(
                "admin",
                "encodedPassword",
                "admin@example.com",
                "ADMIN");

        when(userRepository.findByUsername("admin"))
                .thenReturn(user);

        when(passwordEncoder.matches(
                "wrong",
                "encodedPassword"))
                .thenReturn(false);

        assertFalse(
                userService.authenticateUser(
                        "admin",
                        "wrong"));
    }

    @Test
    void shouldRejectUnknownUser() {
        when(userRepository.findByUsername("unknown"))
                .thenReturn(null);

        assertFalse(
                userService.authenticateUser(
                        "unknown",
                        "password"));

        verifyNoInteractions(passwordEncoder);
    }

    @Test
    void shouldCreateUserWithEncodedPassword() {
        User user = new User(
                "newuser",
                "plainPassword",
                "new@example.com",
                "USER");

        when(passwordEncoder.encode("plainPassword"))
                .thenReturn("encodedPassword");

        when(userRepository.save(user))
                .thenReturn(user);

        User created =
                userService.createUser(user);

        assertSame(user, created);

        assertEquals(
                "encodedPassword",
                created.getPassword());
    }

    @Test
    void shouldUpdateUserPassword() {
        User user = new User(
                "user",
                "oldPassword",
                "user@example.com",
                "USER");

        when(passwordEncoder.encode("newPassword"))
                .thenReturn("encodedNewPassword");

        when(userRepository.save(user))
                .thenReturn(user);

        User updated =
                userService.updateUser(
                        user,
                        "newPassword");

        assertEquals(
                "encodedNewPassword",
                updated.getPassword());
    }

    @Test
    void shouldReturnAllUsers() {
        User user = new User(
                "user",
                "password",
                "user@example.com",
                "USER");

        when(userRepository.findAll())
                .thenReturn(List.of(user));

        List<User> users =
                userService.getAllUsers();

        assertEquals(1, users.size());
        assertEquals(
                "user",
                users.get(0).getUsername());
    }

    @Test
    void shouldFindUserUsingParameterizedQuery() {
        User user = new User(
                "alice",
                "password",
                "alice@example.com",
                "USER");

        Query query = org.mockito.Mockito.mock(Query.class);

        when(entityManager.createNativeQuery(
                anyString(),
                eq(User.class)))
                .thenReturn(query);

        when(query.setParameter(
                "username",
                "alice"))
                .thenReturn(query);

        when(query.getResultList())
                .thenReturn(List.of(user));

        User result =
                userService.findUserByUsername("alice");

        assertEquals("alice", result.getUsername());

        verify(query).setParameter(
                "username",
                "alice");
    }

    @Test
    void shouldReturnNullWhenUserIsNotFound() {
        Query query = org.mockito.Mockito.mock(Query.class);

        when(entityManager.createNativeQuery(
                anyString(),
                eq(User.class)))
                .thenReturn(query);

        when(query.setParameter(
                "username",
                "missing"))
                .thenReturn(query);

        when(query.getResultList())
                .thenReturn(List.of());

        User result =
                userService.findUserByUsername("missing");

        assertNull(result);
    }

    @Test
    void shouldSearchUsersUsingParameterizedQuery() {
        User user = new User(
                "alice",
                "password",
                "alice@example.com",
                "USER");

        Query query = org.mockito.Mockito.mock(Query.class);

        when(entityManager.createNativeQuery(
                anyString(),
                eq(User.class)))
                .thenReturn(query);

        when(query.setParameter(
                "searchTerm",
                "%ali%"))
                .thenReturn(query);

        when(query.getResultList())
                .thenReturn(List.of(user));

        List<User> result =
                userService.searchUsers("ali");

        assertEquals(1, result.size());

        verify(query).setParameter(
                "searchTerm",
                "%ali%");
    }
}