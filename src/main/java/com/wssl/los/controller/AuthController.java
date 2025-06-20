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
import org.springframework.http.HttpStatus;
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

import com.wssl.los.model.ApiResponse;
import com.wssl.los.model.ApplicationDetail;
import com.wssl.los.model.Organization;
import com.wssl.los.model.Otp;
import com.wssl.los.model.Role;
import com.wssl.los.model.User;
import com.wssl.los.repository.ApplicationDetailRepository;
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
	
	@Autowired
	private ApplicationDetailRepository applicationDetailRepository;

	private AtomicLong userSequence = new AtomicLong(1);
	private Map<String, String> otpStore = new HashMap<>();
	private static final int OTP_EXPIRY_MINUTES = 5;

	private String generateOtp() {
		Random random = new Random();
		return String.format("%06d", 100000 + random.nextInt(900000));
	}

	private void sendOtpEmail(String email, String otp) {
		try {
			MimeMessage message = mailSender.createMimeMessage();
			MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");
			helper.setTo(email);
			helper.setSubject("Your OTP for Login");
			helper.setFrom("career@whitestones.co.in");
			String htmlContent = "<html><body>" + "<h2>Your OTP</h2>" + "<p>OTP: <b>" + otp + "</b></p>"
					+ "<p>Valid for " + OTP_EXPIRY_MINUTES + " minutes.</p>" + "</body></html>";
			helper.setText(htmlContent, true);
			mailSender.send(message);
		} catch (MessagingException e) {
			throw new RuntimeException("Failed to send OTP email: " + e.getMessage(), e);
		}
	}

	private void sendPasswordSetupEmail(String email, String token) {
		SimpleMailMessage message = new SimpleMailMessage();
		message.setTo(email);
		message.setSubject("Set Your Password");
		message.setText("Set your password: http://your-app-url/set-password?email=" + email + "&token=" + token
				+ "\nValid for 24 hours.");
		mailSender.send(message);
	}

//    @PostMapping("/send-otp")
//    public ResponseEntity<ApiResponse<Map<String, String>>> login(@RequestBody Map<String, String> request) {
//        String identifier = request.get("username");
//        String password = request.get("password");
//
//        if (identifier == null || password == null) {
//            return ResponseEntity.badRequest()
//                    .body(new ApiResponse<>(HttpStatus.BAD_REQUEST.value(), "Username and password are required"));
//        }
//
//        User user = userRepository.findByEmail(identifier);
//        if (user == null) {
//            user = userRepository.findByUserId(identifier);
//        }
//
//        if (user == null || "Y".equalsIgnoreCase(user.getDelflg()) ||
//                !BCrypt.verifyer().verify(password.toCharArray(), user.getPasswordHash()).verified) {
//            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
//                    .body(new ApiResponse<>(HttpStatus.UNAUTHORIZED.value(), "Invalid credentials or deleted user"));
//        }
//
//        String otpValue = generateOtp();
//        LocalDateTime expiry = LocalDateTime.now().plusMinutes(OTP_EXPIRY_MINUTES);
//
//        Otp otp = new Otp();
//        otp.setEmail(user.getEmail());
//        otp.setOtp(otpValue);
//        otp.setExpiryDate(expiry);
//        otpRepository.save(otp);
//
//        sendOtpEmail(user.getEmail(), otpValue);
//
//        Map<String, String> data = new HashMap<>();
//        data.put("email", user.getEmail());
//        return ResponseEntity.ok(new ApiResponse<>(HttpStatus.OK.value(), "OTP sent to your email", data));
//    }
	@PostMapping("/send-otp")
	public ResponseEntity<ApiResponse<Map<String, String>>> login(@RequestBody Map<String, String> request) {
		String identifier = request.get("username");
		String password = request.get("password");

		if (identifier == null || password == null) {
			return ResponseEntity.badRequest()
					.body(new ApiResponse<>(HttpStatus.BAD_REQUEST.value(), "Username and password are required"));
		}

		User user = userRepository.findByEmail(identifier);
		if (user == null) {
			user = userRepository.findByUserId(identifier);
		}

		if (user == null || "Y".equalsIgnoreCase(user.getDelflg())
				|| !BCrypt.verifyer().verify(password.toCharArray(), user.getPasswordHash()).verified) {
			return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
					.body(new ApiResponse<>(HttpStatus.UNAUTHORIZED.value(), "Invalid credentials or deleted user"));
		}

		// Hardcoded OTP for development/testing
		String otpValue = "123456"; // <--- Replace with generateOtp() for production
		LocalDateTime expiry = LocalDateTime.now().plusMinutes(OTP_EXPIRY_MINUTES);

		Otp otp = new Otp();
		otp.setEmail(user.getEmail());
		otp.setOtp(otpValue);
		otp.setExpiryDate(expiry);
		otpRepository.save(otp);

		sendOtpEmail(user.getEmail(), otpValue); // still sends the hardcoded OTP

		Map<String, String> data = new HashMap<>();
		data.put("email", user.getEmail());
		data.put("otp", otpValue); // optional: useful for frontend testing
		return ResponseEntity.ok(new ApiResponse<>(HttpStatus.OK.value(), "OTP sent to your email", data));
	}

	@PostMapping("/verify-otp")
	public ResponseEntity<ApiResponse<Map<String, Object>>> verifyOtp(@RequestBody Map<String, String> request) {
		String email = request.get("email");
		String otpValue = request.get("otp");

		if (email == null || otpValue == null) {
			return ResponseEntity.badRequest()
					.body(new ApiResponse<>(HttpStatus.BAD_REQUEST.value(), "Email and OTP are required"));
		}

		Optional<Otp> otpOptional = otpRepository.findById(email);
		if (otpOptional.isEmpty() || otpOptional.get().isExpired()) {
			return ResponseEntity.badRequest()
					.body(new ApiResponse<>(HttpStatus.BAD_REQUEST.value(), "OTP expired or invalid"));
		}

		Otp otp = otpOptional.get();
		if (!otp.getOtp().equals(otpValue)) {
			return ResponseEntity.badRequest().body(new ApiResponse<>(HttpStatus.BAD_REQUEST.value(), "Invalid OTP"));
		}

		User user = userRepository.findByEmail(email);
		if (user == null || "Y".equalsIgnoreCase(user.getDelflg())) {
			return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
					.body(new ApiResponse<>(HttpStatus.UNAUTHORIZED.value(), "User not found or deleted"));
		}

		String accessToken = jwtUtil.generateToken(user.getEmail());
		String refreshToken = jwtUtil.generateRefreshToken(user.getEmail());
		refreshTokenService.saveRefreshToken(user.getEmail(), refreshToken);

		otpRepository.deleteById(email);

		Map<String, Object> data = new HashMap<>();
		data.put("token", accessToken);
		data.put("refreshToken", refreshToken);
		data.put("userId", user.getUserId());
		data.put("role", user.getRole() != null ? user.getRole().getRoleName() : null);

		return ResponseEntity.ok(new ApiResponse<>(HttpStatus.OK.value(), "OTP verified successfully", data));
	}

	@PostMapping("/refresh-token")
	public ResponseEntity<ApiResponse<Map<String, String>>> refreshToken(@RequestBody Map<String, String> request) {
		String refreshToken = request.get("refreshToken");

		if (refreshToken == null || !refreshTokenService.isRefreshTokenValid(refreshToken)) {
			return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
					.body(new ApiResponse<>(HttpStatus.UNAUTHORIZED.value(), "Invalid or expired refresh token"));
		}

		String username = jwtUtil.getUsernameFromToken(refreshToken);
		User user = userRepository.findByEmail(username);
		if (user == null || "Y".equalsIgnoreCase(user.getDelflg())) {
			return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
					.body(new ApiResponse<>(HttpStatus.UNAUTHORIZED.value(), "User not found or deleted"));
		}

		String newAccessToken = jwtUtil.generateToken(username);
		String newRefreshToken = jwtUtil.generateRefreshToken(username);
		refreshTokenService.deleteRefreshToken(refreshToken);
		refreshTokenService.saveRefreshToken(username, newRefreshToken);

		Map<String, String> data = new HashMap<>();
		data.put("token", newAccessToken);
		data.put("refreshToken", newRefreshToken);
		return ResponseEntity.ok(new ApiResponse<>(HttpStatus.OK.value(), "Token refreshed successfully", data));
	}

	@PostMapping("/register")
	public ResponseEntity<ApiResponse<Map<String, String>>> register(@RequestBody Map<String, String> request) {
		String email = request.get("email");
		String firstName = request.get("firstName");
		String lastName = request.get("lastName");
		String roleIdStr = request.get("roleId");
		String createdBy = request.get("createdBy");

		if (firstName == null || email == null || roleIdStr == null) {
			return ResponseEntity.badRequest()
					.body(new ApiResponse<>(HttpStatus.BAD_REQUEST.value(), "Missing required fields"));
		}

		if (userRepository.findByEmail(email) != null) {
			return ResponseEntity.badRequest()
					.body(new ApiResponse<>(HttpStatus.BAD_REQUEST.value(), "Email already exists"));
		}

		Long roleId;
		try {
			roleId = Long.parseLong(roleIdStr);
		} catch (NumberFormatException e) {
			return ResponseEntity.badRequest()
					.body(new ApiResponse<>(HttpStatus.BAD_REQUEST.value(), "Invalid roleId format"));
		}

		Role role = roleRepository.findById(roleId).orElse(null);
		if (role == null) {
			return ResponseEntity.badRequest()
					.body(new ApiResponse<>(HttpStatus.BAD_REQUEST.value(), "Role not found"));
		}

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

		Map<String, String> data = new HashMap<>();
		data.put("userId", userId);
		return ResponseEntity.ok(new ApiResponse<>(HttpStatus.OK.value(),
				"Registration successful. Check email for password setup.", data));
	}

	@PostMapping("/create-account")
	public ResponseEntity<ApiResponse<Map<String, String>>> createAccount(@RequestBody Map<String, String> request) {
		String email = request.get("email");
		String firstName = request.get("firstName");
		String lastName = request.get("lastName");
		String password = request.get("password");
		String roleIdStr = request.get("roleId");
		String createdBy = request.get("createdBy");
		String phoneNumber = request.get("phoneNumber");

		if (firstName == null || email == null || roleIdStr == null || password == null) {
			return ResponseEntity.badRequest()
					.body(new ApiResponse<>(HttpStatus.BAD_REQUEST.value(), "Missing required fields"));
		}

		if (userRepository.findByEmail(email) != null) {
			return ResponseEntity.badRequest()
					.body(new ApiResponse<>(HttpStatus.BAD_REQUEST.value(), "Email already exists"));
		}

		Long roleId;
		try {
			roleId = Long.parseLong(roleIdStr);
		} catch (NumberFormatException e) {
			return ResponseEntity.badRequest()
					.body(new ApiResponse<>(HttpStatus.BAD_REQUEST.value(), "Invalid roleId format"));
		}

		Role role = roleRepository.findById(roleId).orElse(null);
		if (role == null) {
			return ResponseEntity.badRequest()
					.body(new ApiResponse<>(HttpStatus.BAD_REQUEST.value(), "Role not found"));
		}

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
		user.setPhone(phoneNumber);

		long count = userRepository.count() + 1;
		String userId = String.format("USR%03d", count);
		user.setUserId(userId);

		userRepository.save(user);

		Map<String, String> data = new HashMap<>();
		data.put("userId", userId);
		return ResponseEntity.ok(new ApiResponse<>(HttpStatus.OK.value(), "Account created successfully", data));
	}

	@PostMapping("/forget-password")
	public ResponseEntity<ApiResponse<String>> forgetPassword(@RequestBody Map<String, String> request) {
		String identifier = request.get("identifier");

		if (identifier == null) {
			return ResponseEntity.badRequest()
					.body(new ApiResponse<>(HttpStatus.BAD_REQUEST.value(), "Identifier is required"));
		}

		User user = userRepository.findByEmail(identifier);
		if (user == null) {
			user = userRepository.findByUserId(identifier);
		}

		if (user == null || "Y".equalsIgnoreCase(user.getDelflg())) {
			return ResponseEntity.badRequest()
					.body(new ApiResponse<>(HttpStatus.BAD_REQUEST.value(), "User not found or deleted"));
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

		return ResponseEntity.ok(new ApiResponse<>(HttpStatus.OK.value(), "OTP sent to registered email", null));
	}

	@PostMapping("/reset-password")
	public ResponseEntity<ApiResponse<String>> resetPassword(@RequestBody Map<String, String> request) {
		String email = request.get("email");
		String otp = request.get("otp");
		String newPassword = request.get("newPassword");

		if (email == null || otp == null || newPassword == null) {
			return ResponseEntity.badRequest().body(
					new ApiResponse<>(HttpStatus.BAD_REQUEST.value(), "Email, OTP, and new password are required"));
		}

		Optional<Otp> otpOptional = otpRepository.findById(email);
		if (otpOptional.isEmpty() || otpOptional.get().isExpired()) {
			return ResponseEntity.badRequest()
					.body(new ApiResponse<>(HttpStatus.BAD_REQUEST.value(), "Invalid or expired OTP"));
		}

		Otp otpEntity = otpOptional.get();
		if (!otpEntity.getOtp().equals(otp)) {
			return ResponseEntity.badRequest().body(new ApiResponse<>(HttpStatus.BAD_REQUEST.value(), "Invalid OTP"));
		}

		User user = userRepository.findByEmail(email);
		if (user == null) {
			return ResponseEntity.badRequest()
					.body(new ApiResponse<>(HttpStatus.BAD_REQUEST.value(), "User not found"));
		}

		user.setPasswordHash(BCrypt.withDefaults().hashToString(12, newPassword.toCharArray()));
		userRepository.save(user);

		otpRepository.deleteById(email);
		return ResponseEntity.ok(new ApiResponse<>(HttpStatus.OK.value(), "Password reset successful", null));
	}

	@PostMapping("/set-password")
	public ResponseEntity<ApiResponse<String>> setPassword(@RequestBody Map<String, String> request) {
		String email = request.get("email");
		String token = request.get("token");
		String password = request.get("password");

		if (email == null || token == null || password == null) {
			return ResponseEntity.badRequest()
					.body(new ApiResponse<>(HttpStatus.BAD_REQUEST.value(), "Email, token, and password are required"));
		}

		String storedToken = otpStore.get(email);
		if (storedToken == null || !storedToken.equals(token)) {
			return ResponseEntity.badRequest()
					.body(new ApiResponse<>(HttpStatus.BAD_REQUEST.value(), "Invalid or expired token"));
		}

		User user = userRepository.findByEmail(email);
		if (user == null) {
			return ResponseEntity.badRequest()
					.body(new ApiResponse<>(HttpStatus.BAD_REQUEST.value(), "User not found"));
		}

		user.setPasswordHash(BCrypt.withDefaults().hashToString(12, password.toCharArray()));
		userRepository.save(user);

		otpStore.remove(email);
		return ResponseEntity.ok(new ApiResponse<>(HttpStatus.OK.value(), "Password set successful", null));
	}

	@GetMapping("/users")
	public ResponseEntity<ApiResponse<List<User>>> getAllUser() {
		List<User> activeUsers = userRepository.findAll().stream()
				.filter(user -> !"Y".equalsIgnoreCase(user.getDelflg())).toList();
		return ResponseEntity.ok(new ApiResponse<>(HttpStatus.OK.value(), "Users retrieved successfully", activeUsers));
	}

	@PostMapping("/roles")
	public ResponseEntity<ApiResponse<Role>> createRole(@RequestBody @Valid Role role) {
		role.setRcreTime(LocalDateTime.now());
		roleRepository.save(role);
		return ResponseEntity.ok(new ApiResponse<>(HttpStatus.OK.value(), "Role created successfully", role));
	}

	@PutMapping("/roles/{id}")
	public ResponseEntity<ApiResponse<Role>> updateRole(@PathVariable Long id, @RequestBody @Valid Role role) {
		Role existingRole = roleRepository.findById(id).orElse(null);
		if (existingRole == null) {
			return ResponseEntity.badRequest()
					.body(new ApiResponse<>(HttpStatus.BAD_REQUEST.value(), "Role not found"));
		}

		if (!"N".equalsIgnoreCase(existingRole.getDelflg())) {
			return ResponseEntity.badRequest()
					.body(new ApiResponse<>(HttpStatus.BAD_REQUEST.value(), "Cannot update a deleted role"));
		}

		existingRole.setRoleName(role.getRoleName());
		existingRole.setDescription(role.getDescription());
		existingRole.setUpdtTime(LocalDateTime.now());
		roleRepository.save(existingRole);

		return ResponseEntity.ok(new ApiResponse<>(HttpStatus.OK.value(), "Role updated successfully", existingRole));
	}

	@DeleteMapping("/roles/{id}")
	public ResponseEntity<ApiResponse<String>> deleteRole(@PathVariable Long id) {
		Role role = roleRepository.findById(id).orElse(null);
		if (role == null) {
			return ResponseEntity.badRequest()
					.body(new ApiResponse<>(HttpStatus.BAD_REQUEST.value(), "Role not found"));
		}

		role.setDelflg("Y");
		role.setUpdtTime(LocalDateTime.now());
		roleRepository.save(role);

		return ResponseEntity.ok(new ApiResponse<>(HttpStatus.OK.value(), "Role marked as deleted", null));
	}

	@GetMapping("/roles")
	public ResponseEntity<ApiResponse<List<Role>>> getAllRoles() {
		List<Role> activeRoles = roleRepository.findByDelflg("N");
		System.out.println("activeRoles>>>>" + activeRoles);
		return ResponseEntity.ok(new ApiResponse<>(HttpStatus.OK.value(), "Roles retrieved successfully", activeRoles));
	}

	@PostMapping("/organizations")
	public ResponseEntity<ApiResponse<Organization>> createOrganization(@RequestParam String name,
			@RequestParam String address, @RequestPart("logo") MultipartFile logo) {
		if (name == null || address == null || logo == null) {
			return ResponseEntity.badRequest()
					.body(new ApiResponse<>(HttpStatus.BAD_REQUEST.value(), "Name, address, and logo are required"));
		}

		Organization org = new Organization();
		org.setName(name);
		org.setAddress(address);
		org.setLogo(logo.getOriginalFilename());
		org.setRcreTime(LocalDateTime.now());
		organizationRepository.save(org);

		return ResponseEntity.ok(new ApiResponse<>(HttpStatus.OK.value(), "Organization created successfully", org));
	}

	@PutMapping("/organizations/{id}")
	public ResponseEntity<ApiResponse<Organization>> updateOrganization(@PathVariable Long id,
			@RequestParam String name, @RequestParam String address,
			@RequestPart(value = "logo", required = false) MultipartFile logo) {
		Organization org = organizationRepository.findById(id).orElse(null);
		if (org == null) {
			return ResponseEntity.badRequest()
					.body(new ApiResponse<>(HttpStatus.BAD_REQUEST.value(), "Organization not found"));
		}

		if (name == null || address == null) {
			return ResponseEntity.badRequest()
					.body(new ApiResponse<>(HttpStatus.BAD_REQUEST.value(), "Name and address are required"));
		}

		org.setName(name);
		org.setAddress(address);
		if (logo != null) {
			org.setLogo(logo.getOriginalFilename());
		}
		org.setUpdtTime(LocalDateTime.now());
		organizationRepository.save(org);

		return ResponseEntity.ok(new ApiResponse<>(HttpStatus.OK.value(), "Organization updated successfully", org));
	}

	@DeleteMapping("/organizations/{id}")
	public ResponseEntity<ApiResponse<String>> deleteOrganization(@PathVariable Long id) {
		Organization org = organizationRepository.findById(id).orElse(null);
		if (org == null) {
			return ResponseEntity.badRequest()
					.body(new ApiResponse<>(HttpStatus.BAD_REQUEST.value(), "Organization not found"));
		}

		organizationRepository.delete(org);
		return ResponseEntity.ok(new ApiResponse<>(HttpStatus.OK.value(), "Organization deleted successfully", null));
	}

	@GetMapping("/organizations")
	public ResponseEntity<ApiResponse<List<Organization>>> getAllOrganizations() {
		List<Organization> organizations = organizationRepository.findAll();
		return ResponseEntity
				.ok(new ApiResponse<>(HttpStatus.OK.value(), "Organizations retrieved successfully", organizations));
	}

	@GetMapping("/fetch-user/{userId}")
	public ResponseEntity<ApiResponse<User>> getUserById(@PathVariable String userId) {
		User user = userRepository.findByUserId(userId);
		if (user == null) {
			return ResponseEntity.status(HttpStatus.NOT_FOUND)
					.body(new ApiResponse<>(HttpStatus.NOT_FOUND.value(), "User not found with ID: " + userId));
		}
		return ResponseEntity.ok(new ApiResponse<>(HttpStatus.OK.value(), "User retrieved successfully", user));
	}

	

	@PostMapping("/add_appdetails")
	public ResponseEntity<ApiResponse<Map<String, Object>>> applicationdetails(
			@RequestBody ApplicationDetail applicationdetails) {
		try {
			// Save application details to DB
			ApplicationDetail savedDetails = applicationDetailRepository.save(applicationdetails);

			// Generate application number
			String applicationNumber = savedDetails.getUserId() + "-" + savedDetails.getId();

			// Prepare response data
			Map<String, Object> responseData = new HashMap<>();
			responseData.put("id", savedDetails.getId());
			responseData.put("userId", savedDetails.getUserId());
			responseData.put("applicationNumber", applicationNumber);

			return ResponseEntity.ok(
					new ApiResponse<>(HttpStatus.OK.value(), "Application details saved successfully", responseData));
		} catch (Exception e) {
			e.printStackTrace(); // Log the error (optional: use logger instead)

			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(new ApiResponse<>(
					HttpStatus.INTERNAL_SERVER_ERROR.value(), "Failed to save application details: " + e.getMessage()));
		}
	}

}