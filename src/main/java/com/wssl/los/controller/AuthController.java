package com.wssl.los.controller;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Random;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicLong;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RequestPart;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import com.wssl.los.model.Organization;
import com.wssl.los.model.Otp;
import com.wssl.los.model.Role;
import com.wssl.los.model.User;
import com.wssl.los.repository.OrganizationRepository;
import com.wssl.los.repository.OtpRepository;
import com.wssl.los.repository.RoleRepository;
import com.wssl.los.repository.UserRepository;
import com.wssl.los.service.RefreshTokenService;
import com.wssl.los.util.JwtUtil;

import at.favre.lib.crypto.bcrypt.BCrypt;
import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import jakarta.validation.Valid;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    @Autowired
    private UserRepository userRepository;
    @Autowired
    private RoleRepository roleRepository;
    @Autowired
    private OrganizationRepository organizationRepository;
    @Autowired
    private OtpRepository otpRepository;
    @Autowired
    private JwtUtil jwtUtil;
    @Autowired
    private JavaMailSender mailSender;
    @Autowired
    private RefreshTokenService refreshTokenService;

    private AtomicLong userSequence = new AtomicLong(1);
    private Map<String, String> otpStore = new HashMap<>(); // For /set-password tokens
    private static final int OTP_EXPIRY_MINUTES = 5;

    // Generate 6-digit OTP
    private String generateOtp() {
        Random random = new Random();
        int otp = 100000 + random.nextInt(900000); // 6-digit OTP
        return String.valueOf(otp);
    }

    // Send OTP email
    private void sendOtpEmail(String email, String otp) {
        try {
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");
            helper.setTo(email);
            helper.setSubject("Your OTP for Login");
            helper.setFrom("career@whitestones.co.in"); 
            // HTML email content using string concatenation
            String htmlContent = "<html>\n" +
                                 "<body style='font-family: Arial, sans-serif; color: #333;'>\n" +
                                 "<h2 style='color: #2E7D32;'>Your One-Time Password (OTP)</h2>\n" +
                                 "<p>Dear User,</p>\n" +
                                 "<p>Your OTP for login is:</p>\n" +
                                 "<p style='font-size: 24px; font-weight: bold; color: #D81B60;'>" + otp + "</p>\n" +
                                 "<p>This OTP is valid for <strong>" + OTP_EXPIRY_MINUTES + " minutes</strong>.</p>\n" +
                                 "<p>Please do not share this OTP with anyone for security reasons.</p>\n" +
                                 "<p>If you did not request this OTP, please contact our support team.</p>\n" +
                                 "<p>Best regards,<br>Your Application Team</p>\n" +
                                 "</body>\n" +
                                 "</html>";

            helper.setText(htmlContent, true);
            mailSender.send(message);
        } catch (MessagingException e) {
            throw new RuntimeException("Failed to send OTP email: " + e.getMessage(), e);
        }
    }

    @PostMapping("/send-otp")
    public ResponseEntity<?> login(@RequestBody Map<String, String> request) {
        String identifier = request.get("username");
        String password = request.get("password");

        User user = userRepository.findByEmail(identifier);
        if (user == null) {
            user = userRepository.findByUserId(identifier);
        }

        if (user != null && "N".equalsIgnoreCase(user.getDelflg())
                && BCrypt.verifyer().verify(password.toCharArray(), user.getPasswordHash()).verified) {

            // Generate and save OTP
            String otpValue = generateOtp();
            LocalDateTime expiry = LocalDateTime.now().plusMinutes(OTP_EXPIRY_MINUTES);
            Otp otp = new Otp();
            otp.setEmail(user.getEmail());
            otp.setOtp(otpValue);
            otp.setExpiryDate(expiry);
            otpRepository.save(otp);

            // Send OTP via email
            try {
                sendOtpEmail(user.getEmail(), otpValue);
            } catch (Exception e) {
                return ResponseEntity.status(500).body("Failed to send OTP: " + e.getMessage());
            }

            // Return temporary response
            Map<String, Object> response = new HashMap<>();
            response.put("message", "OTP sent to your email");
            response.put("email", user.getEmail());
            return ResponseEntity.ok(response);
        }

        return ResponseEntity.status(401).body("Invalid credentials or deleted user");
    }

    @PostMapping("/verify-otp")
    public ResponseEntity<?> verifyOtp(@RequestBody Map<String, String> request) {
        String email = request.get("email");
        String otpValue = request.get("otp");

        Optional<Otp> otpOptional = otpRepository.findById(email);
        if (otpOptional.isEmpty() || otpOptional.get().isExpired()) {
            return ResponseEntity.status(400).body("OTP expired or invalid");
        }

        Otp otp = otpOptional.get();
        if (!otp.getOtp().equals(otpValue)) {
            return ResponseEntity.status(400).body("Invalid OTP");
        }

        // OTP is valid, fetch user
        User user = userRepository.findByEmail(email);
        if (user == null || !"N".equalsIgnoreCase(user.getDelflg())) {
            return ResponseEntity.status(401).body("User not found or deleted");
        }

        // Generate tokens
        String accessToken = jwtUtil.generateToken(user.getEmail());
        String refreshToken = jwtUtil.generateRefreshToken(user.getEmail());

        // Save refresh token
        refreshTokenService.saveRefreshToken(user.getEmail(), refreshToken);

        // Clear OTP
        otpRepository.deleteById(email);

        // Prepare response
        Map<String, Object> response = new HashMap<>();
        response.put("token", accessToken);
        response.put("refreshToken", refreshToken);
        response.put("userId", user.getUserId());
        response.put("role", user.getRole() != null ? user.getRole().getRoleName() : null);

        return ResponseEntity.ok(response);
    }

    @PostMapping("/refresh-token")
    public ResponseEntity<?> refreshToken(@RequestBody Map<String, String> request) {
        String refreshToken = request.get("refreshToken");

        if (refreshToken == null || !refreshTokenService.isRefreshTokenValid(refreshToken)) {
            return ResponseEntity.status(401).body("Invalid or expired refresh token");
        }

        String username = jwtUtil.getUsernameFromToken(refreshToken);
        User user = userRepository.findByEmail(username);
        if (user == null || !"N".equalsIgnoreCase(user.getDelflg())) {
            return ResponseEntity.status(401).body("User not found or deleted");
        }

        String newAccessToken = jwtUtil.generateToken(username);
        String newRefreshToken = jwtUtil.generateRefreshToken(username);
        refreshTokenService.deleteRefreshToken(refreshToken);
        refreshTokenService.saveRefreshToken(username, newRefreshToken);

        Map<String, Object> response = new HashMap<>();
        response.put("token", newAccessToken);
        response.put("refreshToken", newRefreshToken);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody Map<String, String> request) {
        String email = request.get("email");
        String firstName = request.get("firstName");
        String lastName = request.get("lastName");
        String roleIdStr = request.get("roleId");
        String createdBy = request.get("createdBy");

        if (firstName == null || email == null || roleIdStr == null) {
            return ResponseEntity.badRequest().body("Missing required fields");
        }

        if (userRepository.findByEmail(email) != null) {
            return ResponseEntity.badRequest().body("Email already exists");
        }

        Long roleId;
        try {
            roleId = Long.parseLong(roleIdStr);
        } catch (NumberFormatException e) {
            return ResponseEntity.badRequest().body("Invalid roleId format");
        }

        // Fixed orElseThrow syntax
        Role role = roleRepository.findById(roleId).orElseThrow(() -> new RuntimeException("Role not found"));

        User user = new User();
        user.setEmail(email);
        user.setFirstName(firstName);
        user.setLastName(lastName);
        user.setRole(role);
        user.setRcreationTime(LocalDateTime.now());
        user.setRcreationUser(createdBy != null ? createdBy : "system");
        user.setDelflg("N");
        user.setActive(true);

        long count = userRepository.count() + 1;
        String userId = String.format("USR%03d", count);
        user.setUserId(userId);

        String token = UUID.randomUUID().toString();
        otpStore.put(email, token);
        userRepository.save(user);

        sendPasswordSetupEmail(email, token);

        Map<String, String> response = new HashMap<>();
        response.put("userId", userId);
        response.put("message", "Registration successful. Check email for password setup.");
        return ResponseEntity.ok(response);
    }

    @PostMapping("/create-account")
    public ResponseEntity<?> createAccount(@RequestBody Map<String, String> request) {
        String email = request.get("email");
        String firstName = request.get("firstName");
        String lastName = request.get("lastName");
        String password = request.get("password");
        String roleIdStr = request.get("roleId");
        String createdBy = request.get("createdBy");

        if (firstName == null || email == null || roleIdStr == null || password == null) {
            return ResponseEntity.badRequest().body("Missing required fields");
        }

        if (userRepository.findByEmail(email) != null) {
            return ResponseEntity.badRequest().body("Email already exists");
        }

        Long roleId;
        try {
            roleId = Long.parseLong(roleIdStr);
        } catch (NumberFormatException e) {
            return ResponseEntity.badRequest().body("Invalid roleId format");
        }

        // Fixed orElseThrow syntax
        Role role = roleRepository.findById(roleId).orElseThrow(() -> new RuntimeException("Role not found"));

        User user = new User();
        user.setEmail(email);
        user.setFirstName(firstName);
        user.setLastName(lastName);
        user.setPasswordHash(BCrypt.withDefaults().hashToString(12, password.toCharArray()));
        user.setRole(role);
        user.setRcreationTime(LocalDateTime.now());
        user.setRcreationUser(createdBy != null ? createdBy : "system");
        user.setDelflg("N");
        user.setActive(true);

        long count = userRepository.count() + 1;
        String userId = String.format("USR%03d", count);
        user.setUserId(userId);

        userRepository.save(user);

        Map<String, String> response = new HashMap<>();
        response.put("userId", userId);
        response.put("message", "Account created successfully");
        return ResponseEntity.ok(response);
    }

    @PostMapping("/forget-password")
    public ResponseEntity<?> forgetPassword(@RequestBody Map<String, String> request) {
        String identifier = request.get("identifier");

        User user = userRepository.findByEmail(identifier);
        if (user == null) {
            user = userRepository.findByUserId(identifier);
        }

        if (user == null || "Y".equalsIgnoreCase(user.getDelflg())) {
            return ResponseEntity.badRequest().body("User not found or deleted");
        }

        String otp = String.format("%06d", (int) (Math.random() * 1000000));
        Otp otpEntity = new Otp();
        otpEntity.setEmail(user.getEmail());
        otpEntity.setOtp(otp);
        otpEntity.setExpiryDate(LocalDateTime.now().plusMinutes(10));
        otpRepository.save(otpEntity);

        SimpleMailMessage message = new SimpleMailMessage();
        message.setTo(user.getEmail());
        message.setSubject("Password Reset OTP");
        message.setText("Your OTP for password reset is: " + otp + "\nValid for 10 minutes.");
        mailSender.send(message);

        return ResponseEntity.ok("OTP sent to registered email");
    }

    @PostMapping("/reset-password")
    public ResponseEntity<?> resetPassword(@RequestBody Map<String, String> request) {
        String email = request.get("email");
        String otp = request.get("otp");
        String newPassword = request.get("newPassword");

        Optional<Otp> otpOptional = otpRepository.findById(email);
        if (otpOptional.isEmpty() || otpOptional.get().isExpired()) {
            return ResponseEntity.badRequest().body("Invalid or expired OTP");
        }

        Otp otpEntity = otpOptional.get();
        if (!otpEntity.getOtp().equals(otp)) {
            return ResponseEntity.badRequest().body("Invalid OTP");
        }

        User user = userRepository.findByEmail(email);
        if (user == null) {
            return ResponseEntity.badRequest().body("User not found");
        }

        user.setPasswordHash(BCrypt.withDefaults().hashToString(12, newPassword.toCharArray()));
        userRepository.save(user);

        otpRepository.deleteById(email);
        return ResponseEntity.ok("Password reset successful");
    }

    @PostMapping("/set-password")
    public ResponseEntity<?> setPassword(@RequestBody Map<String, String> request) {
        String email = request.get("email");
        String token = request.get("token");
        String password = request.get("password");

        String storedToken = otpStore.get(email);
        if (storedToken == null || !storedToken.equals(token)) {
            return ResponseEntity.badRequest().body("Invalid or expired token");
        }

        User user = userRepository.findByEmail(email);
        if (user == null) {
            return ResponseEntity.badRequest().body("User not found");
        }

        user.setPasswordHash(BCrypt.withDefaults().hashToString(12, password.toCharArray()));
        userRepository.save(user);

        otpStore.remove(email);
        return ResponseEntity.ok("Password set successful");
    }

    private void sendPasswordSetupEmail(String email, String token) {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setTo(email);
        message.setSubject("Set Your Password");
        message.setText("Please set your password using this link: http://your-app-url/set-password?email=" + email
                + "&token=" + token + "\nLink valid for 24 hours.");
        mailSender.send(message);
    }

    @GetMapping("/users")
    public ResponseEntity<List<User>> getAllUser() {
        List<User> activeUsers = userRepository.findAll().stream()
                .filter(user -> !"Y".equalsIgnoreCase(user.getDelflg())).toList();
        return ResponseEntity.ok(activeUsers);
    }

    @PostMapping("/roles")
    public ResponseEntity<?> createRole(@RequestBody @Valid Role role) {
        role.setRcreTime(LocalDateTime.now());
        roleRepository.save(role);
        return ResponseEntity.ok(role);
    }

    @PutMapping("/roles/{id}")
    public ResponseEntity<?> updateRole(@PathVariable Long id, @RequestBody @Valid Role role) {
        Role existingRole = roleRepository.findById(id).orElseThrow(() -> new RuntimeException("Role not found"));

        existingRole.setRoleName(role.getRoleName());
        existingRole.setDescription(role.getDescription());
        existingRole.setUpdtTime(LocalDateTime.now());

        roleRepository.save(existingRole);
        return ResponseEntity.ok(existingRole);
    }

    @GetMapping("/roles")
    public ResponseEntity<List<Role>> getAllRoles() {
        return ResponseEntity.ok(roleRepository.findAll());
    }

    @PostMapping("/organizations")
    public ResponseEntity<?> createOrganization(@RequestParam String name, @RequestParam String address,
            @RequestPart("logo") MultipartFile logo) {
        Organization org = new Organization();
        org.setName(name);
        org.setAddress(address);
        org.setLogo(logo.getOriginalFilename());
        org.setRcreTime(LocalDateTime.now());

        organizationRepository.save(org);
        return ResponseEntity.ok(org);
    }

    @PutMapping("/organizations/{id}")
    public ResponseEntity<?> updateOrganization(@PathVariable Long id, @RequestParam String name,
            @RequestParam String address, @RequestPart(value = "logo", required = false) MultipartFile logo) {
        Organization org = organizationRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Role not found"));

        org.setName(name);
        org.setAddress(address);
        if (logo != null) {
            org.setLogo(logo.getOriginalFilename());
        }
        org.setUpdtTime(LocalDateTime.now());

        organizationRepository.save(org);
        return ResponseEntity.ok(org);
    }

    @DeleteMapping("/organizations/{id}")
    public ResponseEntity<?> deleteOrganization(@PathVariable Long id) {
        Organization org = organizationRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Organization not found"));

        organizationRepository.delete(org);
        return ResponseEntity.ok("Organization deleted successfully");
    }

    @GetMapping("/organizations")
    public ResponseEntity<List<Organization>> getAllOrganizations() {
        return ResponseEntity.ok(organizationRepository.findAll());
    }
}