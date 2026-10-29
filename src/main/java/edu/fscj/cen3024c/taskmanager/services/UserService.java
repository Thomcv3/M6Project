package edu.fscj.cen3024c.taskmanager.services;

import edu.fscj.cen3024c.taskmanager.dto.CreateUserRequestDTO;
import edu.fscj.cen3024c.taskmanager.dto.UpdateUserRequestDTO;
import edu.fscj.cen3024c.taskmanager.dto.UserDTO;
import edu.fscj.cen3024c.taskmanager.entities.Task;
import edu.fscj.cen3024c.taskmanager.entities.User;
import edu.fscj.cen3024c.taskmanager.exceptions.UserNotFoundException;
import edu.fscj.cen3024c.taskmanager.repositories.UserRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

@Service
public class UserService {

    private static final int SALT_BYTES = 16;
    private static final int ITERATIONS = 600000;
    private static final int KEY_LENGTH = 256;

    private final UserRepository userRepository;
    private final SecureRandom secureRandom = new SecureRandom();

    public UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Transactional(readOnly = true)
    public List<UserDTO> findAll() {
        return userRepository.findAll()
                .stream()
                .map(this::convertToDTO)
                .collect(Collectors.toList());
    }

    @Transactional(readOnly = true)
    public UserDTO findById(Integer id) {
        User user = findByIdEntity(id);
        return convertToDTO(user);
    }

    @Transactional(readOnly = true)
    public User findByIdEntity(Integer id) {
        return userRepository.findById(id)
                .orElseThrow(() -> new UserNotFoundException(id));
    }

    @Transactional
    public UserDTO createUser(CreateUserRequestDTO request) {
        if (userRepository.findByUsername(request.getUsername()).isPresent()) {
            throw new IllegalArgumentException("Username already exists");
        }

        User user = new User();
        user.setUsername(request.getUsername());
        setNewPassword(user, request.getPassword());

        User savedUser = userRepository.save(user);
        return convertToDTO(savedUser);
    }

    @Transactional
    public UserDTO updateUser(Integer id, UpdateUserRequestDTO request) {
        User existingUser = findByIdEntity(id);

        existingUser.setUsername(request.getUsername());

        if (request.getPassword() != null && !request.getPassword().isBlank()) {
            setNewPassword(existingUser, request.getPassword());
        }

        User updatedUser = userRepository.save(existingUser);
        return convertToDTO(updatedUser);
    }

    @Transactional
    public void deleteById(Integer id) {
        if (!userRepository.existsById(id)) {
            throw new UserNotFoundException(id);
        }
        userRepository.deleteById(id);
    }

    @Transactional(readOnly = true)
    public Optional<UserDTO> login(String username, String rawPassword) {
        return userRepository.findByUsername(username)
                .filter(user -> verifyPassword(rawPassword, user))
                .map(this::convertToDTO);
    }

    public boolean verifyPassword(String rawPassword, User user) {
        if (rawPassword == null || user.getSalt() == null
                || user.getPasswordHash() == null) {
            return false;
        }

        try {
            byte[] saltBytes = Base64.getDecoder().decode(user.getSalt());
            byte[] expectedHash = Base64.getDecoder().decode(user.getPasswordHash());
            byte[] actualHash = hashPassword(rawPassword, saltBytes);

            return MessageDigest.isEqual(expectedHash, actualHash);
        } catch (IllegalArgumentException ex) {
            return false;
        }
    }

    private void setNewPassword(User user, String rawPassword) {
        if (rawPassword == null || rawPassword.isBlank()) {
            throw new IllegalArgumentException("Password is required");
        }

        byte[] saltBytes = new byte[SALT_BYTES];
        secureRandom.nextBytes(saltBytes);

        user.setSalt(Base64.getEncoder().encodeToString(saltBytes));
        user.setPasswordHash(
                Base64.getEncoder().encodeToString(hashPassword(rawPassword, saltBytes))
        );
    }

    private byte[] hashPassword(String password, byte[] saltBytes) {
        PBEKeySpec spec = new PBEKeySpec(
                password.toCharArray(), saltBytes, ITERATIONS, KEY_LENGTH
        );

        try {
            return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
                    .generateSecret(spec)
                    .getEncoded();
        } catch (Exception ex) {
            throw new IllegalStateException("Unable to hash password", ex);
        } finally {
            spec.clearPassword();
        }
    }

    public UserDTO convertToDTO(User user) {
        Set<String> taskTitles = user.getTasks() != null
                ? user.getTasks().stream()
                    .map(Task::getTitle)
                    .collect(Collectors.toSet())
                : Set.of();

        return new UserDTO(
                user.getId(),
                user.getUsername(),
                taskTitles
        );
    }
}
