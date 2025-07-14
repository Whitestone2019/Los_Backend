package com.wssl.los.controller;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Random;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Sort;
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

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.wssl.los.model.AcceptOffer;
import com.wssl.los.model.ApiResponse;
import com.wssl.los.model.ApplicationDetail;
import com.wssl.los.model.ApprovalProcessFlow;
import com.wssl.los.model.DocumentVerification;
import com.wssl.los.model.FundedInfo;
import com.wssl.los.model.LinkBankAccount;
import com.wssl.los.model.LoanType;
import com.wssl.los.model.Menu;
import com.wssl.los.model.Organization;
import com.wssl.los.model.Otp;
import com.wssl.los.model.ReviewAndAgreement;
import com.wssl.los.model.Role;
import com.wssl.los.model.RoleMenuPermission;
import com.wssl.los.model.User;
import com.wssl.los.repository.AcceptOfferRepository;
import com.wssl.los.repository.ApplicationDetailRepository;
import com.wssl.los.repository.ApprovalProcessFlowRepository;
import com.wssl.los.repository.ApprovalStep;
import com.wssl.los.repository.DocumentverificationRepository;
import com.wssl.los.repository.FundedRepository;
import com.wssl.los.repository.LinkBankAccountRepository;
import com.wssl.los.repository.LoanTypeRepository;
import com.wssl.los.repository.LoanTypeWorkflow;
import com.wssl.los.repository.LoanTypeWorkflowRepository;
import com.wssl.los.repository.MenuRepository;
import com.wssl.los.repository.OrganizationRepository;
import com.wssl.los.repository.OtpRepository;
import com.wssl.los.repository.ReviewAndAgreementRepository;
import com.wssl.los.repository.RoleMenuPermissionRepository;
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
	private RoleMenuPermissionRepository permissionRepository;
	@Autowired
	private MenuRepository menuRepository;

	@Autowired
	private ApplicationDetailRepository applicationDetailRepository;

	@Autowired
	private LoanTypeRepository loanTypeRepository;
	
	@Autowired
	private LoanTypeWorkflowRepository loanTypeWorkflowRepository;

	@Autowired
	private ApprovalProcessFlowRepository flowRepository;

	@Autowired
	private LinkBankAccountRepository linkedbankaccountRepository;
	@Autowired
	private DocumentverificationRepository documentVerificationRepository;
	@Autowired
	private AcceptOfferRepository acceptOfferRepository;
	@Autowired
	private ReviewAndAgreementRepository reviewAndAgreementRepository;
	@Autowired
	private FundedRepository fundedInfoRepository;

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
		message.setText("Set your password: http://152.67.189.231:8844/reset_password?email=" + email + "&token="
				+ token + "\nValid for 24 hours.");
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

		// sendOtpEmail(user.getEmail(), otpValue); // still sends the hardcoded OTP

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
		data.put("roleId", user.getRole().getId());

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
		String phone = request.get("phone");
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
		user.setPhone(phone);
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
		String phone = request.get("phone");

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
		user.setPhone(phone);
		user.setRcreationTime(LocalDateTime.now());
		user.setRcreationUser(createdBy != null ? createdBy : "system");
		user.setDelflg("N");
		user.setActive(true);
		long count = userRepository.count() + 1;
		String userId = String.format("USR%03d", count);
		user.setUserId(userId);

		userRepository.save(user);

		Map<String, String> data = new HashMap<>();
		data.put("userId", userId);
		return ResponseEntity.ok(new ApiResponse<>(HttpStatus.OK.value(), "Account created successfully", data));
	}

//		@PostMapping("/forget-password")
//		public ResponseEntity<ApiResponse<String>> forgetPassword(@RequestBody Map<String, String> request) {
//			String identifier = request.get("userId");
//	
//			if (identifier == null) {
//				return ResponseEntity.badRequest()
//						.body(new ApiResponse<>(HttpStatus.BAD_REQUEST.value(), "Identifier is required"));
//			}
//	
//			User user = userRepository.findByEmail(identifier);
//			if (user == null) {
//				user = userRepository.findByUserId(identifier);
//			}
//	
//			if (user == null || "Y".equalsIgnoreCase(user.getDelflg())) {
//				return ResponseEntity.badRequest()
//						.body(new ApiResponse<>(HttpStatus.BAD_REQUEST.value(), "User not found or deleted"));
//			}
//	
//			String otp = String.format("%06d", (int) (Math.random() * 1000000));
//			Otp otpEntity = new Otp();
//			otpEntity.setEmail(user.getEmail());
//			otpEntity.setOtp(otp);
//			otpEntity.setExpiryDate(LocalDateTime.now().plusMinutes(10));
//			otpRepository.save(otpEntity);
//	
//			SimpleMailMessage message = new SimpleMailMessage();
//			message.setTo(user.getEmail());
//			message.setSubject("Password Reset OTP");
//			message.setText("Your OTP for password reset is: " + otp + "\nValid for 10 minutes.");
//			mailSender.send(message);
//	
//			return ResponseEntity.ok(new ApiResponse<>(HttpStatus.OK.value(), "OTP sent to registered email", null));
//		}
//	
//		@PostMapping("/reset-password")
//		public ResponseEntity<ApiResponse<String>> resetPassword(@RequestBody Map<String, String> request) {
//			String email = request.get("email");
//			String otp = request.get("otp");
//			String newPassword = request.get("newPassword");
//	
//			if (email == null || otp == null || newPassword == null) {
//				return ResponseEntity.badRequest().body(
//						new ApiResponse<>(HttpStatus.BAD_REQUEST.value(), "Email, OTP, and new password are required"));
//			}
//	
//			Optional<Otp> otpOptional = otpRepository.findById(email);
//			if (otpOptional.isEmpty() || otpOptional.get().isExpired()) {
//				return ResponseEntity.badRequest()
//						.body(new ApiResponse<>(HttpStatus.BAD_REQUEST.value(), "Invalid or expired OTP"));
//			}
//	
//			Otp otpEntity = otpOptional.get();
//			if (!otpEntity.getOtp().equals(otp)) {
//				return ResponseEntity.badRequest().body(new ApiResponse<>(HttpStatus.BAD_REQUEST.value(), "Invalid OTP"));
//			}
//	
//			User user = userRepository.findByEmail(email);
//			if (user == null) {
//				return ResponseEntity.badRequest()
//						.body(new ApiResponse<>(HttpStatus.BAD_REQUEST.value(), "User not found"));
//			}
//	
//			user.setPasswordHash(BCrypt.withDefaults().hashToString(12, newPassword.toCharArray()));
//			userRepository.save(user);
//	
//			otpRepository.deleteById(email);
//			return ResponseEntity.ok(new ApiResponse<>(HttpStatus.OK.value(), "Password reset successful", null));
//		}

	// hardcode OTP

	@PostMapping("/forget-password")
	public ResponseEntity<ApiResponse<String>> forgetPassword(@RequestBody Map<String, String> request) {
		String identifier = request.get("userId");

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

		// Hardcoded OTP for testing
		String otp = "123456"; // <-- Hardcoded OTP instead of random

		Otp otpEntity = new Otp();
		otpEntity.setEmail(user.getEmail());
		otpEntity.setOtp(otp);
		otpEntity.setExpiryDate(LocalDateTime.now().plusMinutes(10));
		otpRepository.save(otpEntity);

		// Email notification
//		SimpleMailMessage message = new SimpleMailMessage();
//		message.setTo(user.getEmail());
//		message.setSubject("Password Reset OTP");
//		message.setText("Your OTP for password reset is: " + otp + "\nValid for 10 minutes.");
//		mailSender.send(message);

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

		// Compare with hardcoded OTP
		if (!otpEntity.getOtp().equals("123456")) { // <-- Hardcoded OTP comparison
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

	@PostMapping("/savePermissions")
	public ResponseEntity<ApiResponse<String>> savePermissions(@RequestBody List<RoleMenuPermission> permissions) {
		for (RoleMenuPermission permission : permissions) {
			permission.setUpdtTime(java.time.LocalDateTime.now());
			permissionRepository.save(permission);
		}

		return ResponseEntity.ok(new ApiResponse<>(200, "Permissions saved successfully", null));
	}

	@GetMapping("/getPermissionsWithMenuName/{roleId}")
	public ResponseEntity<ApiResponse<List<Map<String, Object>>>> getPermissionsWithMenuName(
			@PathVariable Long roleId) {
		List<Map<String, Object>> permissions = permissionRepository.getPermissionsWithMenuName(roleId);
		return ResponseEntity.ok(new ApiResponse<>(200, "Permissions fetched successfully", permissions));
	}

	@PostMapping("/save-parent")
	public ResponseEntity<ApiResponse<Menu>> saveParentMenu(@RequestBody Map<String, String> request) {
		String menuName = request.get("menuName");
		String url = request.get("url");
		String icon = request.get("icon");

		if (menuName == null || url == null) {
			return ResponseEntity.badRequest().body(new ApiResponse<>(400, "Menu name and URL are required", null));
		}

		Menu menu = new Menu();
		menu.setMenuName(menuName);
		menu.setUrl(url);
		menu.setIcon(icon);
		menu.setDelflg("N");
		menu.setParent(null); // it's a parent menu

		Menu saved = menuRepository.save(menu);

		return ResponseEntity.ok(new ApiResponse<>(200, "Parent menu saved successfully", saved));
	}

	@GetMapping("/all-menus")
	public ResponseEntity<ApiResponse<List<Menu>>> getAllMenus() {
		List<Menu> menus = menuRepository.findAll();
		return ResponseEntity.ok(new ApiResponse<>(200, "", menus));
	}

	// Save Loan Type
	@PostMapping("/loan-type/save")
	public ResponseEntity<ApiResponse<String>> saveLoanType(@RequestBody LoanType loanType) {
	    Optional<LoanType> existing = loanTypeRepository.findByLoanType(loanType.getLoanType());

	    if (existing.isPresent()) {
	        LoanType update = existing.get();
	        update.setDescription(loanType.getDescription());
	        update.setApprovalSetup(loanType.getApprovalSetup()); // Optional: only if needed
	        loanTypeRepository.save(update);
	        return ResponseEntity.ok(new ApiResponse<>(200, "Loan type updated successfully", null));
	    } else {
	        loanTypeRepository.save(loanType);
	        return ResponseEntity.ok(new ApiResponse<>(200, "Loan type saved successfully", null));
	    }
	}

	@PutMapping("/loan-type/update-approval-setup/{loanType}")
	public ResponseEntity<ApiResponse<String>> updateApprovalSetup(
	        @PathVariable String loanType,
	        @RequestBody List<ApprovalStep> approvalSteps) {

	    Optional<LoanType> existing = loanTypeRepository.findByLoanType(loanType);

	    if (existing.isPresent()) {
	        LoanType update = existing.get();
	        try {
	            String approvalSetupJson = new ObjectMapper().writeValueAsString(approvalSteps);
	            update.setApprovalSetup(approvalSetupJson);
	            loanTypeRepository.save(update);
	            return ResponseEntity.ok(new ApiResponse<>(200, "Approval setup updated successfully", null));
	        } catch (JsonProcessingException e) {
	            e.printStackTrace();
	            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
	                    .body(new ApiResponse<>(500, "Failed to convert approval setup to JSON", null));
	        }
	    } else {
	        return ResponseEntity.status(HttpStatus.NOT_FOUND)
	                .body(new ApiResponse<>(404, "Loan type not found", null));
	    }
	}

	
	// Get All Loan Types
	@GetMapping("/loan-types")
	public ResponseEntity<ApiResponse<List<LoanType>>> getAllLoanTypes() {
		return ResponseEntity.ok(new ApiResponse<>(200, "Loan types fetched", loanTypeRepository.findAll()));
	}

	@PostMapping("/workflow-save")
	public ResponseEntity<ApiResponse<String>> saveFlow(@RequestBody ApprovalProcessFlow flow) {
		Optional<ApprovalProcessFlow> existing = flowRepository.findByLoanType(flow.getLoanType());

		if (existing.isPresent()) {
			ApprovalProcessFlow updated = existing.get();
			updated.setSteps(flow.getSteps());
			flowRepository.save(updated);
			return ResponseEntity.ok(new ApiResponse<>(200, "Approval flow updated successfully.", null));
		} else {
			flowRepository.save(flow);
			return ResponseEntity.ok(new ApiResponse<>(200, "Approval flow saved successfully.", null));
		}
	}

	@GetMapping("/workflow-get/{loanType}")
	public ResponseEntity<ApiResponse<ApprovalProcessFlow>> getFlow(@PathVariable String loanType) {
		Optional<ApprovalProcessFlow> flowOpt = flowRepository.findByLoanType(loanType);

		if (flowOpt.isPresent()) {
			return ResponseEntity.ok(new ApiResponse<>(200, "Approval flow fetched", flowOpt.get()));
		} else {
			return ResponseEntity.status(404).body(new ApiResponse<>(404, "Loan type not found.", null));
		}
	}

	@GetMapping("/getMenusWithPermissions/{roleId}")
	public ResponseEntity<ApiResponse<List<Map<String, Object>>>> getMenusWithPermissions(@PathVariable Long roleId) {

		// Step 1: Fetch all menus
		List<Menu> allMenus = menuRepository.findAll(Sort.by("id"));

		// Step 2: Get role-based permissions
		List<Map<String, Object>> rolePermissions = permissionRepository.getPermissionsWithMenuName(roleId);

		Map<Long, Map<String, Object>> permissionMap = new HashMap<>();
		for (Map<String, Object> perm : rolePermissions) {
			Long menuId = ((Number) perm.get("menuId")).longValue();
			permissionMap.put(menuId, perm);
		}

		// Step 3: Group submenus by parent ID
		Map<Long, List<Menu>> subMenuMap = allMenus.stream().filter(menu -> menu.getParent() != null)
				.collect(Collectors.groupingBy(menu -> menu.getParent().getId()));

		// Step 4: Process only top-level menus (parent is null)
		List<Map<String, Object>> combinedList = new ArrayList<>();

		for (Menu menu : allMenus) {
			if (menu.getParent() != null)
				continue;

			Map<String, Object> result = new LinkedHashMap<>();
			result.put("menuId", menu.getId());
			result.put("menuName", menu.getMenuName());
			result.put("url", menu.getUrl());
			result.put("icon", menu.getIcon());
			result.put("type", menu.getType());

			Map<String, Object> perms = permissionMap.get(menu.getId());
			result.put("canRead", perms != null && Boolean.TRUE.equals(perms.get("canRead")));
			result.put("canWrite", perms != null && Boolean.TRUE.equals(perms.get("canWrite")));
			result.put("canAll", perms != null && Boolean.TRUE.equals(perms.get("canAll")));

			// 🟢 Recursively add submenus
			result.put("subMenus", buildSubMenuTree(menu.getId(), subMenuMap, permissionMap));

			combinedList.add(result);
		}

		return ResponseEntity.ok(new ApiResponse<>(200, "Menus with permissions fetched successfully", combinedList));
	}

	private List<Map<String, Object>> buildSubMenuTree(Long parentId, Map<Long, List<Menu>> subMenuMap,
			Map<Long, Map<String, Object>> permissionMap) {
		List<Map<String, Object>> children = new ArrayList<>();

		if (!subMenuMap.containsKey(parentId))
			return children;

		for (Menu sub : subMenuMap.get(parentId)) {
			Map<String, Object> child = new LinkedHashMap<>();
			child.put("menuId", sub.getId());
			child.put("menuName", sub.getMenuName());
			child.put("url", sub.getUrl());
			child.put("icon", sub.getIcon());
			child.put("type", sub.getType());

			Map<String, Object> subPerms = permissionMap.get(sub.getId());
			child.put("canRead", subPerms != null && Boolean.TRUE.equals(subPerms.get("canRead")));
			child.put("canWrite", subPerms != null && Boolean.TRUE.equals(subPerms.get("canWrite")));
			child.put("canAll", subPerms != null && Boolean.TRUE.equals(subPerms.get("canAll")));

// 🟢 Recursively add sub-submenus
			child.put("subMenus", buildSubMenuTree(sub.getId(), subMenuMap, permissionMap));

			children.add(child);
		}

		return children;
	}

	@PostMapping("/add_appdetails")
	public ResponseEntity<ApiResponse<Map<String, Object>>> applicationdetails(
			@RequestBody ApplicationDetail applicationdetails) {

		try {
			String inputUserId = applicationdetails.getUserId();
			if (inputUserId == null || inputUserId.isBlank()) {
				return ResponseEntity.badRequest()
						.body(new ApiResponse<>(HttpStatus.BAD_REQUEST.value(), "Missing userId in request"));
			}

			// ✅ Check if userId exists in User table
			Optional<User> user = userRepository.findByUserIdAndDelflg(inputUserId, "N");
			if (user.isEmpty()) {
				return ResponseEntity.badRequest()
						.body(new ApiResponse<>(HttpStatus.BAD_REQUEST.value(), "Invalid userId: " + inputUserId));
			}

			// ✅ Print userId to console
			System.out.println("User ID from DB: " + user.get().getUserId());

			// ✅ Set other fields
			applicationdetails.setDelFlag("N");
			applicationdetails.setCreatedDate(LocalDateTime.now());

			// ✅ Save first to generate ID
			ApplicationDetail savedDetails = applicationDetailRepository.save(applicationdetails);

			// ✅ Save updated application number
			applicationDetailRepository.save(savedDetails);

			// ✅ Prepare response
			Map<String, Object> responseData = new HashMap<>();
			responseData.put("id", savedDetails.getId());
			responseData.put("userId", savedDetails.getUserId());

			return ResponseEntity.ok(
					new ApiResponse<>(HttpStatus.OK.value(), "Application details saved successfully", responseData));

		} catch (Exception e) {
			e.printStackTrace();
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(new ApiResponse<>(
					HttpStatus.INTERNAL_SERVER_ERROR.value(), "Failed to save application details: " + e.getMessage()));
		}
	}

	@GetMapping("/get_applicationdetailsonly_by_user/{userId}")
	public ResponseEntity<ApiResponse<Map<String, Object>>> getApplicationOnlyByUser(@PathVariable String userId) {
	    try {
	        // Fetch ApplicationDetail by userId and delFlag = 'N'
	        ApplicationDetail app = applicationDetailRepository.findByUserIdAndDelFlag(userId, "N");

	        if (app == null) {
	            return ResponseEntity.status(HttpStatus.NOT_FOUND)
	                .body(new ApiResponse<>(HttpStatus.NOT_FOUND.value(), "Application details not found for user", null));
	        }

	        Map<String, Object> applicationData = new LinkedHashMap<>();
	        applicationData.put("applicationId", app.getId());
	        applicationData.put("dateOfBirth", app.getDateOfBirth());
	        applicationData.put("monthlyGrossIncome", app.getMonthlyGrossIncome());
	        applicationData.put("ssn", app.getSsn());
	        applicationData.put("confirmSsn", app.getConfirmSsn());
	        applicationData.put("howMuchDoYouNeed", app.getHowMuchDoYouNeed());
	        applicationData.put("homeAddress", app.getHomeAddress());
	        applicationData.put("homeAddress2", app.getHomeAddress2());
	        applicationData.put("zipCode", app.getZipCode());
	        applicationData.put("city", app.getCity());
	        applicationData.put("state", app.getState());
	        applicationData.put("isHomeOwner", app.getIsHomeOwner());
	        applicationData.put("createdBy", app.getCreatedBy());
	        applicationData.put("createdDate", app.getCreatedDate());
	        applicationData.put("updatedBy", app.getUpdatedBy());
	        applicationData.put("updatedDate", app.getUpdatedDate());

	        return ResponseEntity.ok(new ApiResponse<>(HttpStatus.OK.value(),
	            "Application details retrieved successfully", applicationData));

	    } catch (Exception e) {
	        e.printStackTrace();
	        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
	            .body(new ApiResponse<>(HttpStatus.INTERNAL_SERVER_ERROR.value(),
	                "Error retrieving application details: " + e.getMessage(), null));
	    }
	}
	

	@DeleteMapping("/delete_application_by_user/{userId}")
	public ResponseEntity<ApiResponse<String>> deleteApplicationByUserId(@PathVariable String userId) {
	    try {
	        // ? Fetch application by userId and delFlag = 'N'
	        ApplicationDetail application = applicationDetailRepository.findByUserIdAndDelFlag(userId, "N");

	        if (application == null) {
	            return ResponseEntity.status(HttpStatus.NOT_FOUND)
	                    .body(new ApiResponse<>(HttpStatus.NOT_FOUND.value(),
	                            "Application not found for userId: " + userId));
	        }

	        // ? Perform soft delete
	        application.setDelFlag("Y");
	        application.setUpdatedDate(LocalDateTime.now());
	        applicationDetailRepository.save(application);

	        return ResponseEntity.ok(new ApiResponse<>(HttpStatus.OK.value(),
	                "Application soft-deleted successfully for userId: " + userId));

	    } catch (Exception e) {
	        e.printStackTrace();
	        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(new ApiResponse<>(
	                HttpStatus.INTERNAL_SERVER_ERROR.value(),
	                "Failed to delete application: " + e.getMessage()));
	    }
	}
	@GetMapping("/getapplicationCount")
	public ResponseEntity<ApiResponse<Long>> getApplicationCount() {
		try {
			long appCount = applicationDetailRepository.countByDelFlag("N");
			return ResponseEntity
					.ok(new ApiResponse<>(HttpStatus.OK.value(), "Application count retrieved successfully", appCount));
		} catch (Exception e) {

			e.printStackTrace();
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
					.body(new ApiResponse<>(HttpStatus.INTERNAL_SERVER_ERROR.value(),
							"Failed to retrieve application count: " + e.getMessage(), null));
		}
	}


	@PostMapping("/addOrUpdate_applicationBankdetails")
	public ResponseEntity<ApiResponse<Map<String, Object>>> addOrUpdateBankAccount(
			@RequestBody LinkBankAccount incoming) {
		Map<String, Object> response = new HashMap<>();

		try {
			// Step 1: Validate input
			if (incoming.getApplicationDetail()==null
					|| incoming.getApplicationDetail().getApplicationNumber() == null) {
				return ResponseEntity.badRequest().body(new ApiResponse<>(HttpStatus.BAD_REQUEST.value(),
						"Application number must not be null.", null));
			}

			String applicationNumber= incoming.getApplicationDetail().getApplicationNumber();

			// Step 2: Fetch ApplicationDetail (along with User)
			LoanTypeWorkflow application = loanTypeWorkflowRepository.findByApplicationNumberAndDelFlag(applicationNumber, "N");

			if (application == null) {
				return ResponseEntity.status(HttpStatus.NOT_FOUND).body(new ApiResponse<>(HttpStatus.NOT_FOUND.value(),
						"Invalid or deleted application number.", null));
			}

			User user = application.getUser();

			if (user == null) {
				return ResponseEntity.status(HttpStatus.NOT_FOUND).body(
						new ApiResponse<>(HttpStatus.NOT_FOUND.value(), "User not found for the application.", null));
			}

			String userId = user.getUserId();

			// Step 3: Check if bank account already exists
			Optional<LinkBankAccount> existingOpt = linkedbankaccountRepository
					.findByUser_UserIdAndApplicationDetail_ApplicationNumber(userId, applicationNumber);

			boolean isUpdate = existingOpt.isPresent();
			LinkBankAccount account = existingOpt.orElse(new LinkBankAccount());

			// Step 4: Set values
			account.setUser(user);
			account.setApplicationDetail(application);
			account.setApplicationDetail(application);
			account.setAccountHolderName(incoming.getAccountHolderName());
			account.setBankName(incoming.getBankName());
			account.setAccountNumber(incoming.getAccountNumber());
			account.setIfscCode(incoming.getIfscCode());
			account.setAccountType(incoming.getAccountType());
			account.setIsAuthorized(incoming.getIsAuthorized());
			account.setDelFlag("N");
			account.setCreatedDate(LocalDateTime.now());

			// Step 5: Save to DB
			LinkBankAccount saved = linkedbankaccountRepository.save(account);

			// Step 6: Prepare response
			response.put("accountId", saved.getId());
			response.put("applicationNumber", application.getApplicationNumber());
			response.put("loanType", application.getLoanType());
			response.put("delFlag", saved.getDelFlag());

			String message = isUpdate ? "Bank account updated successfully." : "Bank account added successfully.";
			return ResponseEntity.ok(new ApiResponse<>(HttpStatus.OK.value(), message, response));

		} catch (Exception e) {
			e.printStackTrace();
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
					.body(new ApiResponse<>(HttpStatus.INTERNAL_SERVER_ERROR.value(),
							"An unexpected error occurred while saving bank account details: " + e.getMessage(), null));
		}
	}

	@GetMapping("/get_linkedBankAccountsdetailsonly/{applicationNumber}")
	public ResponseEntity<ApiResponse<List<Map<String, Object>>>> getLinkedBankAccountsByApplication(
			@PathVariable String applicationNumber) {
		try {
			// Check if application exists and is not deleted
			LoanTypeWorkflow app = loanTypeWorkflowRepository.findByApplicationNumberAndDelFlag(applicationNumber,
					"N");
			if (app == null) {
				return ResponseEntity.status(HttpStatus.NOT_FOUND)
						.body(new ApiResponse<>(HttpStatus.NOT_FOUND.value(), "Application not found", null));
			}

			// Fetch linked bank accounts
			List<LinkBankAccount> bankAccounts = linkedbankaccountRepository
					.findByApplicationDetail_ApplicationNumberAndDelFlag(applicationNumber, "N");

			if (bankAccounts.isEmpty()) {
				return ResponseEntity.status(HttpStatus.NOT_FOUND)
						.body(new ApiResponse<>(HttpStatus.NOT_FOUND.value(), "No linked bank accounts found", null));
			}

			// Build response list
			List<Map<String, Object>> bankList = new ArrayList<>();
			for (LinkBankAccount bank : bankAccounts) {
				Map<String, Object> bankData = new LinkedHashMap<>();
				bankData.put("accountId", bank.getId());
				bankData.put("accountHolderName", bank.getAccountHolderName());
				bankData.put("bankName", bank.getBankName());
				bankData.put("accountNumber", bank.getAccountNumber());
				bankData.put("ifscCode", bank.getIfscCode());
				bankData.put("accountType", bank.getAccountType());
				bankData.put("isAuthorized", bank.getIsAuthorized());
				bankData.put("createdDate", bank.getCreatedDate());
				bankList.add(bankData);
			}

			return ResponseEntity.ok(new ApiResponse<>(HttpStatus.OK.value(),
					"Linked bank account details retrieved successfully", bankList));

		} catch (Exception e) {
			e.printStackTrace();
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
					.body(new ApiResponse<>(HttpStatus.INTERNAL_SERVER_ERROR.value(),
							"Error occurred while fetching linked bank accounts: " + e.getMessage(), null));
		}
	}

	@DeleteMapping("/delete_Linked_applicationdetails/{applicationNumber}")
	public ResponseEntity<ApiResponse<String>> softDeleteLinkedBankAccounts(@PathVariable String applicationNumber) {
		try {
			// Step 1: Check if application exists
			LoanTypeWorkflow application = loanTypeWorkflowRepository
					.findByApplicationNumberAndDelFlag(applicationNumber, "N");

			if (application == null) {
				return ResponseEntity.status(HttpStatus.NOT_FOUND)
						.body(new ApiResponse<>(HttpStatus.NOT_FOUND.value(), "Application not found", null));
			}

			// Step 2: Find all active bank accounts linked to the application
			List<LinkBankAccount> bankAccounts = linkedbankaccountRepository
					.findByApplicationDetail_ApplicationNumberAndDelFlag(applicationNumber, "N");

			if (bankAccounts.isEmpty()) {
				return ResponseEntity.status(HttpStatus.NOT_FOUND).body(
						new ApiResponse<>(HttpStatus.NOT_FOUND.value(), "No active linked bank accounts found", null));
			}

			// Step 3: Soft delete each account
			for (LinkBankAccount account : bankAccounts) {
				account.setDelFlag("Y");
				account.setCreatedDate(LocalDateTime.now()); // Optional: update timestamp
			}

			linkedbankaccountRepository.saveAll(bankAccounts);

			return ResponseEntity
					.ok(new ApiResponse<>(HttpStatus.OK.value(), "Linked bank accounts deleted successfully", null));

		} catch (Exception e) {
			e.printStackTrace();
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
					.body(new ApiResponse<>(HttpStatus.INTERNAL_SERVER_ERROR.value(),
							"Error deleting bank account details: " + e.getMessage(), null));
		}
	}

	@PostMapping("/addOrUpdate_Application_documentDeatils")
	public ResponseEntity<ApiResponse<Map<String, Object>>> addOrUpdateDocument(
			@RequestBody DocumentVerification incoming) {

		Map<String, Object> response = new HashMap<>();

		try {
			// Step 1: Validate input
			if (incoming.getApplicationNumber() == null || incoming.getUser() == null) {
				return ResponseEntity.badRequest().body(new ApiResponse<>(HttpStatus.BAD_REQUEST.value(),
						"Application number and user info must not be null.", null));
			}

			String applicationNumber = incoming.getApplicationNumber();
			String userId = incoming.getUser().getUserId();

			// Step 2: Fetch application and user (read-only)
			LoanTypeWorkflow application = loanTypeWorkflowRepository
					.findByApplicationNumberAndDelFlag(applicationNumber, "N");

			if (application == null) {
				return ResponseEntity.status(HttpStatus.NOT_FOUND).body(new ApiResponse<>(HttpStatus.NOT_FOUND.value(),
						"Invalid or deleted application number.", null));
			}

			User user = application.getUser();

			if (user == null || !user.getUserId().equals(userId)) {
				return ResponseEntity.status(HttpStatus.NOT_FOUND).body(new ApiResponse<>(HttpStatus.NOT_FOUND.value(),
						"User not found or does not match application.", null));
			}

			// Step 3: Check for existing document
			Optional<DocumentVerification> existingOpt = documentVerificationRepository
					.findByApplicationNumberAndUser_UserIdAndDocumentNumberAndDelFlag(applicationNumber, userId,
							incoming.getDocumentNumber(), "N");

			boolean isUpdate = existingOpt.isPresent();
			DocumentVerification document = existingOpt.orElse(new DocumentVerification());

			// Step 4: Set values
			document.setApplicationNumber(applicationNumber);
			document.setUser(user);
			document.setDocumentType(incoming.getDocumentType());
			document.setDocumentNumber(incoming.getDocumentNumber());
			document.setIssueDate(incoming.getIssueDate());
			document.setExpiryDate(incoming.getExpiryDate());
			document.setIssuingAuthority(incoming.getIssuingAuthority());
			document.setFilePath(incoming.getFilePath());
			document.setConsentGiven(incoming.getConsentGiven());
			document.setDelFlag("N");
			document.setCreatedAt(LocalDateTime.now());

			// Step 5: Save to DB
			DocumentVerification saved = documentVerificationRepository.save(document);

			// Step 6: Prepare response
			response.put("documentId", saved.getId());
			response.put("applicationNumber", applicationNumber);
			response.put("documentType", saved.getDocumentType());
			response.put("userId", userId);
			response.put("delFlag", saved.getDelFlag());

			String message = isUpdate ? "Document verification updated successfully."
					: "Document verification added successfully.";
			return ResponseEntity.ok(new ApiResponse<>(HttpStatus.OK.value(), message, response));

		} catch (Exception e) {
			e.printStackTrace();
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
					.body(new ApiResponse<>(HttpStatus.INTERNAL_SERVER_ERROR.value(),
							"An unexpected error occurred while saving document verification: " + e.getMessage(),
							null));
		}
	}

	@GetMapping("/get_only_one_document_detail/{applicationNumber}")
	public ResponseEntity<ApiResponse<Map<String, Object>>> getOnlyOneDocumentDetail(
			@PathVariable String applicationNumber) {
		try {
			// Step 1: Check application and user
			LoanTypeWorkflow application = loanTypeWorkflowRepository
					.findByApplicationNumberAndDelFlag(applicationNumber, "N");
			if (application == null || application.getUser() == null) {
				return ResponseEntity.status(HttpStatus.NOT_FOUND)
						.body(new ApiResponse<>(HttpStatus.NOT_FOUND.value(), "Application or user not found", null));
			}

			User user = application.getUser();

			// Step 2: Fetch one document
			List<DocumentVerification> documents = documentVerificationRepository
					.findByApplicationNumberAndUser_UserIdAndDelFlag(applicationNumber, user.getUserId(), "N");

			if (documents.isEmpty()) {
				return ResponseEntity.status(HttpStatus.NOT_FOUND)
						.body(new ApiResponse<>(HttpStatus.NOT_FOUND.value(), "No document details found", null));
			}

			DocumentVerification doc = documents.get(0); // pick the first one
			Map<String, Object> docData = new LinkedHashMap<>();
			docData.put("documentId", doc.getId());
			docData.put("documentType", doc.getDocumentType());
			docData.put("documentNumber", doc.getDocumentNumber());
			docData.put("issueDate", doc.getIssueDate());
			docData.put("expiryDate", doc.getExpiryDate());
			docData.put("issuingAuthority", doc.getIssuingAuthority());
			docData.put("filePath", doc.getFilePath());
			docData.put("consentGiven", doc.getConsentGiven());
			docData.put("createdAt", doc.getCreatedAt());

			return ResponseEntity.ok(new ApiResponse<>(HttpStatus.OK.value(),
					"Single document verification detail retrieved successfully", docData));
		} catch (Exception e) {
			e.printStackTrace();
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
					.body(new ApiResponse<>(HttpStatus.INTERNAL_SERVER_ERROR.value(),
							"Error retrieving document details: " + e.getMessage(), null));
		}
	}

	@DeleteMapping("/delete_application_documentdetails/{applicationNumber}")
	public ResponseEntity<ApiResponse<String>> Deletedocmentdails(@PathVariable String applicationNumber) {
		try {
			// Step 1: Check if application exists
			LoanTypeWorkflow application = loanTypeWorkflowRepository
					.findByApplicationNumberAndDelFlag(applicationNumber, "N");

			if (application == null) {
				return ResponseEntity.status(HttpStatus.NOT_FOUND)
						.body(new ApiResponse<>(HttpStatus.NOT_FOUND.value(), "Application not found", null));
			}

			String userId = application.getUser() != null ? application.getUser().getUserId() : null;

			// Step 2: Delete Linked Bank Accounts
			List<LinkBankAccount> bankAccounts = linkedbankaccountRepository
					.findByApplicationDetail_ApplicationNumberAndDelFlag(applicationNumber, "N");

			for (LinkBankAccount account : bankAccounts) {
				account.setDelFlag("Y");
				account.setCreatedDate(LocalDateTime.now()); // Optional update
			}
			linkedbankaccountRepository.saveAll(bankAccounts);

			// Step 3: Delete Document Verifications
			if (userId != null) {
				List<DocumentVerification> documents = documentVerificationRepository
						.findByApplicationNumberAndUser_UserIdAndDelFlag(applicationNumber, userId, "N");

				for (DocumentVerification doc : documents) {
					doc.setDelFlag("Y");
					doc.setCreatedAt(LocalDateTime.now()); // Optional update
				}
				documentVerificationRepository.saveAll(documents);
			}

			return ResponseEntity.ok(new ApiResponse<>(HttpStatus.OK.value(),
					"Linked bank accounts and document verifications deleted successfully", null));

		} catch (Exception e) {
			e.printStackTrace();
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(new ApiResponse<>(
					HttpStatus.INTERNAL_SERVER_ERROR.value(), "Error deleting linked data: " + e.getMessage(), null));
		}
	}

	@PostMapping("/addOrUpdate_Application_acceptOffer")
	public ResponseEntity<ApiResponse<Map<String, Object>>> addOrUpdateAcceptOffer(@RequestBody AcceptOffer incoming) {

		Map<String, Object> response = new HashMap<>();

		try {
			// Step 1: Validate input
			if (incoming.getApplicationDetail() == null || incoming.getUser() == null) {
				return ResponseEntity.badRequest().body(new ApiResponse<>(HttpStatus.BAD_REQUEST.value(),
						"Application and user info must not be null.", null));
			}

			String applicationNumber = incoming.getApplicationDetail().getApplicationNumber();
			String userId = incoming.getUser().getUserId();

			// Step 2: Fetch application and user (read-only)
			LoanTypeWorkflow application = loanTypeWorkflowRepository
					.findByApplicationNumberAndDelFlag(applicationNumber, "N");

			if (application == null) {
				return ResponseEntity.status(HttpStatus.NOT_FOUND).body(new ApiResponse<>(HttpStatus.NOT_FOUND.value(),
						"Invalid or deleted application number.", null));
			}

			User user = application.getUser();

			if (user == null || !user.getUserId().equals(userId)) {
				return ResponseEntity.status(HttpStatus.NOT_FOUND).body(new ApiResponse<>(HttpStatus.NOT_FOUND.value(),
						"User not found or does not match application.", null));
			}

			// Step 3: Check for existing offer
			Optional<AcceptOffer> existingOpt = acceptOfferRepository
					.findByApplicationDetail_ApplicationNumberAndUser_UserIdAndDelFlag(applicationNumber, userId, "N");

			boolean isUpdate = existingOpt.isPresent();
			AcceptOffer offer = existingOpt.orElse(new AcceptOffer());

			// ✅ Step 4: Set required fields
			offer.setApplicationDetail(application);
			offer.setApplicationNumber(application.getApplicationNumber()); // ✅ THIS FIXES YOUR ERROR
			offer.setUser(user);
			offer.setLoanAmount(incoming.getLoanAmount());
			offer.setTenureMonths(incoming.getTenureMonths());
			offer.setInterestRate(incoming.getInterestRate());
			offer.setEstimatedEmi(incoming.getEstimatedEmi());
			offer.setConsentGiven(incoming.getConsentGiven());
			offer.setDelFlag("N");
			offer.setCreatedAt(LocalDateTime.now());

			// Step 5: Save to DB
			AcceptOffer saved = acceptOfferRepository.save(offer);

			// Step 6: Prepare response
			response.put("offerId", saved.getId());
			response.put("applicationNumber", applicationNumber);
			response.put("loanAmount", saved.getLoanAmount());
			response.put("tenureMonths", saved.getTenureMonths());
			response.put("interestRate", saved.getInterestRate());
			response.put("estimatedEmi", saved.getEstimatedEmi());
			response.put("userId", userId);
			response.put("consentGiven", saved.getConsentGiven());
			response.put("delFlag", saved.getDelFlag());

			String message = isUpdate ? "Accept offer updated successfully." : "Accept offer added successfully.";
			return ResponseEntity.ok(new ApiResponse<>(HttpStatus.OK.value(), message, response));

		} catch (Exception e) {
			e.printStackTrace();
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
					.body(new ApiResponse<>(HttpStatus.INTERNAL_SERVER_ERROR.value(),
							"An unexpected error occurred while saving offer: " + e.getMessage(), null));
		}
	}

	@GetMapping("/get_accept_offer_detailsonly/{applicationNumber}")
	public ResponseEntity<ApiResponse<Map<String, Object>>> getAcceptOfferDetailsByApplicationNumber(
			@PathVariable String applicationNumber) {
		try {
			// Step 1: Find application
			LoanTypeWorkflow application = loanTypeWorkflowRepository
					.findByApplicationNumberAndDelFlag(applicationNumber, "N");
			if (application == null || application.getUser() == null) {
				return ResponseEntity.status(HttpStatus.NOT_FOUND)
						.body(new ApiResponse<>(HttpStatus.NOT_FOUND.value(), "Application or user not found", null));
			}

			User user = application.getUser();

			// Step 2: Find AcceptOffer
			Optional<AcceptOffer> offerOpt = acceptOfferRepository
					.findByApplicationDetail_ApplicationNumberAndUser_UserIdAndDelFlag(applicationNumber,
							user.getUserId(), "N");

			if (offerOpt.isEmpty()) {
				return ResponseEntity.status(HttpStatus.NOT_FOUND)
						.body(new ApiResponse<>(HttpStatus.NOT_FOUND.value(), "No accept offer details found", null));
			}

			AcceptOffer offer = offerOpt.get();
			Map<String, Object> offerData = new LinkedHashMap<>();
			offerData.put("offerId", offer.getId());
			offerData.put("loanAmount", offer.getLoanAmount());
			offerData.put("tenureMonths", offer.getTenureMonths());
			offerData.put("interestRate", offer.getInterestRate());
			offerData.put("estimatedEmi", offer.getEstimatedEmi());
			offerData.put("consentGiven", offer.getConsentGiven());
			offerData.put("createdAt", offer.getCreatedAt());

			return ResponseEntity.ok(
					new ApiResponse<>(HttpStatus.OK.value(), "Accept offer details retrieved successfully", offerData));
		} catch (Exception e) {
			e.printStackTrace();
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
					.body(new ApiResponse<>(HttpStatus.INTERNAL_SERVER_ERROR.value(),
							"Error retrieving accept offer details: " + e.getMessage(), null));
		}
	}

	@DeleteMapping("/delete_application_acceptoffer_details/{applicationNumber}")
	public ResponseEntity<ApiResponse<String>> deleteAcceptOfferDetails(@PathVariable String applicationNumber) {
		try {
			// Step 1: Fetch the application
			LoanTypeWorkflow application = loanTypeWorkflowRepository
					.findByApplicationNumberAndDelFlag(applicationNumber, "N");

			if (application == null) {
				return ResponseEntity.status(HttpStatus.NOT_FOUND)
						.body(new ApiResponse<>(HttpStatus.NOT_FOUND.value(), "Application not found", null));
			}

			User user = application.getUser();
			if (user == null) {
				return ResponseEntity.status(HttpStatus.NOT_FOUND).body(
						new ApiResponse<>(HttpStatus.NOT_FOUND.value(), "User not found for this application", null));
			}

			// Step 2: Fetch Accept Offer (if exists)
			Optional<AcceptOffer> offerOpt = acceptOfferRepository
					.findByApplicationDetail_IdAndUser_UserIdAndDelFlag(application.getId(), user.getUserId(), "N");

			if (offerOpt.isPresent()) {
				AcceptOffer offer = offerOpt.get();
				offer.setDelFlag("Y");
				offer.setCreatedAt(LocalDateTime.now()); // optional: mark time of logical deletion
				acceptOfferRepository.save(offer);

				return ResponseEntity.ok(new ApiResponse<>(HttpStatus.OK.value(),
						"Accept offer data marked as deleted successfully", null));
			} else {
				return ResponseEntity.status(HttpStatus.NOT_FOUND)
						.body(new ApiResponse<>(HttpStatus.NOT_FOUND.value(), "No accept offer record found", null));
			}

		} catch (Exception e) {
			e.printStackTrace();
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
					.body(new ApiResponse<>(HttpStatus.INTERNAL_SERVER_ERROR.value(),
							"Error deleting accept offer details: " + e.getMessage(), null));
		}
	}

	@PostMapping("/addOrUpdate_Application_reviewAgreement")
	public ResponseEntity<ApiResponse<Map<String, Object>>> addOrUpdateReviewAgreement(
			@RequestBody ReviewAndAgreement incoming) {

		Map<String, Object> response = new HashMap<>();

		try {
			// Step 1: Validate input
			if (incoming.getApplicationNumber() == null || incoming.getUserId() == null) {
				return ResponseEntity.badRequest().body(new ApiResponse<>(HttpStatus.BAD_REQUEST.value(),
						"Application number and user ID must not be null.", null));
			}

			String applicationNumber = incoming.getApplicationNumber();
			String userId = incoming.getUserId();

			// Step 2: Get ApplicationDetail for reference (optional, but useful for
			// linking)
			LoanTypeWorkflow appDetail = loanTypeWorkflowRepository
					.findByApplicationNumberAndDelFlag(applicationNumber, "N");
			if (appDetail == null) {
				return ResponseEntity.status(HttpStatus.NOT_FOUND).body(
						new ApiResponse<>(HttpStatus.NOT_FOUND.value(), "Application not found or deleted.", null));
			}

			// Step 3: Check for existing ReviewAndAgreement record
			Optional<ReviewAndAgreement> existingOpt = reviewAndAgreementRepository
					.findByApplicationNumberAndUserIdAndDelFlag(applicationNumber, userId, "N");

			boolean isUpdate = existingOpt.isPresent();
			ReviewAndAgreement agreement = existingOpt.orElse(new ReviewAndAgreement());

			// Step 4: Set fields
			agreement.setApplicationDetail(appDetail);
			agreement.setApplicationNumber(applicationNumber);
			agreement.setUserId(userId);
			agreement.setInfoConfirmed(incoming.getInfoConfirmed());
			agreement.setTermsAgreed(incoming.getTermsAgreed());
			agreement.setIdentityAuthorized(incoming.getIdentityAuthorized());
			agreement.setFullName(incoming.getFullName());
			agreement.setSignatureType(incoming.getSignatureType());
			agreement.setSignatureMethod(incoming.getSignatureMethod());
			agreement.setSignaturePath(incoming.getSignaturePath());
			agreement.setDelFlag("N");

			if (!isUpdate) {
				agreement.setCreatedAt(LocalDateTime.now());
			}

			// Step 5: Save
			ReviewAndAgreement saved = reviewAndAgreementRepository.save(agreement);

			// Step 6: Prepare response
			response.put("reviewAgreementId", saved.getId());
			response.put("applicationNumber", saved.getApplicationNumber());
			response.put("userId", saved.getUserId());
			response.put("infoConfirmed", saved.getInfoConfirmed());
			response.put("termsAgreed", saved.getTermsAgreed());
			response.put("identityAuthorized", saved.getIdentityAuthorized());
			response.put("fullName", saved.getFullName());
			response.put("signatureType", saved.getSignatureType());
			response.put("signatureMethod", saved.getSignatureMethod());
			response.put("signaturePath", saved.getSignaturePath());
			response.put("createdAt", saved.getCreatedAt());
			response.put("delFlag", saved.getDelFlag());

			String message = isUpdate ? "Review and agreement updated successfully."
					: "Review and agreement added successfully.";
			return ResponseEntity.ok(new ApiResponse<>(HttpStatus.OK.value(), message, response));

		} catch (Exception e) {
			e.printStackTrace();
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
					.body(new ApiResponse<>(HttpStatus.INTERNAL_SERVER_ERROR.value(),
							"An unexpected error occurred while saving review and agreement: " + e.getMessage(), null));
		}
	}

	@GetMapping("/get_reviewandagreement_by_application_only/{applicationNumber}")
	public ResponseEntity<ApiResponse<Map<String, Object>>> getReviewAndAgreementByAppNumber(
			@PathVariable String applicationNumber) {
		try {
			// Step 1: Fetch application by application number and delFlag
			LoanTypeWorkflow application = loanTypeWorkflowRepository
					.findByApplicationNumberAndDelFlag(applicationNumber, "N");

			if (application == null) {
				return ResponseEntity.status(HttpStatus.NOT_FOUND)
						.body(new ApiResponse<>(HttpStatus.NOT_FOUND.value(), "Application not found", null));
			}

			User user = application.getUser();
			if (user == null) {
				return ResponseEntity.status(HttpStatus.NOT_FOUND).body(
						new ApiResponse<>(HttpStatus.NOT_FOUND.value(), "User not associated with application", null));
			}

			// Step 2: Fetch review and agreement
			Optional<ReviewAndAgreement> agreementOpt = reviewAndAgreementRepository
					.findByApplicationNumberAndUserIdAndDelFlag(applicationNumber, user.getUserId(), "N");

			if (agreementOpt.isEmpty()) {
				return ResponseEntity.status(HttpStatus.NOT_FOUND).body(new ApiResponse<>(HttpStatus.NOT_FOUND.value(),
						"Review and agreement details not found", null));
			}

			ReviewAndAgreement agreement = agreementOpt.get();
			Map<String, Object> agreementData = new LinkedHashMap<>();
			agreementData.put("reviewAgreementId", agreement.getId());
			agreementData.put("infoConfirmed", agreement.getInfoConfirmed());
			agreementData.put("termsAgreed", agreement.getTermsAgreed());
			agreementData.put("identityAuthorized", agreement.getIdentityAuthorized());
			agreementData.put("fullName", agreement.getFullName());
			agreementData.put("signatureType", agreement.getSignatureType());
			agreementData.put("signatureMethod", agreement.getSignatureMethod());
			agreementData.put("signaturePath", agreement.getSignaturePath());
			agreementData.put("createdAt", agreement.getCreatedAt());
			agreementData.put("delFlag", agreement.getDelFlag());

			return ResponseEntity.ok(new ApiResponse<>(HttpStatus.OK.value(),
					"Review and agreement details retrieved successfully", agreementData));
		} catch (Exception e) {
			e.printStackTrace();
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
					.body(new ApiResponse<>(HttpStatus.INTERNAL_SERVER_ERROR.value(),
							"Error retrieving review and agreement details: " + e.getMessage(), null));
		}
	}

	@DeleteMapping("/delete_Application_reviewandsignAgreementdetails/{applicationNumber}")
	public ResponseEntity<ApiResponse<String>> deleteReviewAndSignAgreement(@PathVariable String applicationNumber) {
		try {
			// Step 1: Fetch the application
			LoanTypeWorkflow application = loanTypeWorkflowRepository
					.findByApplicationNumberAndDelFlag(applicationNumber, "N");

			if (application == null) {
				return ResponseEntity.status(HttpStatus.NOT_FOUND)
						.body(new ApiResponse<>(HttpStatus.NOT_FOUND.value(), "Application not found", null));
			}

			User user = application.getUser();
			if (user == null) {
				return ResponseEntity.status(HttpStatus.NOT_FOUND).body(
						new ApiResponse<>(HttpStatus.NOT_FOUND.value(), "User not found for this application", null));
			}

			// Step 2: Fetch ReviewAndAgreement (if exists)
			Optional<ReviewAndAgreement> agreementOpt = reviewAndAgreementRepository
					.findByApplicationNumberAndUserIdAndDelFlag(applicationNumber, user.getUserId(), "N");

			if (agreementOpt.isPresent()) {
				ReviewAndAgreement agreement = agreementOpt.get();
				agreement.setDelFlag("Y");
				agreement.setCreatedAt(LocalDateTime.now()); // optional: mark time of logical deletion
				reviewAndAgreementRepository.save(agreement);

				return ResponseEntity.ok(new ApiResponse<>(HttpStatus.OK.value(),
						"Review and agreement data marked as deleted successfully", null));
			} else {
				return ResponseEntity.status(HttpStatus.NOT_FOUND).body(
						new ApiResponse<>(HttpStatus.NOT_FOUND.value(), "No review and agreement record found", null));
			}

		} catch (Exception e) {
			e.printStackTrace();
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
					.body(new ApiResponse<>(HttpStatus.INTERNAL_SERVER_ERROR.value(),
							"Error deleting review and agreement details: " + e.getMessage(), null));
		}
	}

	@PostMapping("/addOrUpdate_Application_fundedInfo")
	public ResponseEntity<ApiResponse<Map<String, Object>>> addOrUpdateFundedInfo(@RequestBody FundedInfo incoming) {

		Map<String, Object> response = new HashMap<>();

		try {
			// Step 1: Validate input
			if (incoming.getApplicationNumber() == null || incoming.getUserId() == null) {
				return ResponseEntity.badRequest().body(new ApiResponse<>(HttpStatus.BAD_REQUEST.value(),
						"Application number and user ID must not be null.", null));
			}

			String applicationNumber = incoming.getApplicationNumber();
			String userId = incoming.getUserId();

			// Step 2: Get ApplicationDetail for reference
			LoanTypeWorkflow appDetail = loanTypeWorkflowRepository
					.findByApplicationNumberAndDelFlag(applicationNumber, "N");
			if (appDetail == null) {
				return ResponseEntity.status(HttpStatus.NOT_FOUND).body(
						new ApiResponse<>(HttpStatus.NOT_FOUND.value(), "Application not found or deleted.", null));
			}

			// Step 3: Check if FundedInfo already exists
			Optional<FundedInfo> existingOpt = fundedInfoRepository
					.findByApplicationNumberAndUserIdAndDelFlag(applicationNumber, userId, "N");

			boolean isUpdate = existingOpt.isPresent();
			FundedInfo funded = existingOpt.orElse(new FundedInfo());

			// Step 4: Set fields
			funded.setApplicationDetail(appDetail);
			funded.setApplicationNumber(applicationNumber);
			funded.setUserId(userId);
			funded.setFundingAmount(incoming.getFundingAmount());
			funded.setFundingDate(incoming.getFundingDate());
			funded.setConfirmFunding(incoming.getConfirmFunding());
			funded.setDelFlag("N");

			if (!isUpdate) {
				funded.setCreatedBy(incoming.getCreatedBy());
				funded.setCreatedDate(LocalDateTime.now());
			}

			funded.setUpdatedBy(incoming.getUpdatedBy());
			funded.setUpdatedDate(LocalDateTime.now());

			// Step 5: Save
			FundedInfo saved = fundedInfoRepository.save(funded);

			// Step 6: Prepare response
			response.put("fundedId", saved.getId());
			response.put("applicationNumber", saved.getApplicationNumber());
			response.put("userId", saved.getUserId());
			response.put("fundingAmount", saved.getFundingAmount());
			response.put("fundingDate", saved.getFundingDate());
			response.put("confirmFunding", saved.getConfirmFunding());
			response.put("createdBy", saved.getCreatedBy());
			response.put("createdDate", saved.getCreatedDate());
			response.put("updatedBy", saved.getUpdatedBy());
			response.put("updatedDate", saved.getUpdatedDate());
			response.put("delFlag", saved.getDelFlag());

			String message = isUpdate ? "Funded info updated successfully." : "Funded info added successfully.";
			return ResponseEntity.ok(new ApiResponse<>(HttpStatus.OK.value(), message, response));

		} catch (Exception e) {
			e.printStackTrace();
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
					.body(new ApiResponse<>(HttpStatus.INTERNAL_SERVER_ERROR.value(),
							"An unexpected error occurred while saving funded info: " + e.getMessage(), null));
		}
	}

	@GetMapping("/get_allApplicationDetails")
	public ResponseEntity<ApiResponse<List<Map<String, Object>>>> getAllApplicationCompleteDetails() {
		try {
			List<ApplicationDetail> applications = applicationDetailRepository.findAll();

			List<Map<String, Object>> responseList = applications.stream()
					.filter(app -> !"Y".equalsIgnoreCase(app.getDelFlag())).map(app -> {
						Map<String, Object> responseMap = new LinkedHashMap<>();

						// Application Info
						Map<String, Object> applicationData = new LinkedHashMap<>();
						applicationData.put("applicationId", app.getId());
						//applicationData.put("applicationNumber", app.getApplicationNumber());
						applicationData.put("dateOfBirth", app.getDateOfBirth());
						applicationData.put("monthlyGrossIncome", app.getMonthlyGrossIncome());
						applicationData.put("ssn", app.getSsn());
						applicationData.put("confirmSsn", app.getConfirmSsn());
						applicationData.put("howMuchDoYouNeed", app.getHowMuchDoYouNeed());
						applicationData.put("homeAddress", app.getHomeAddress());
						applicationData.put("homeAddress2", app.getHomeAddress2());
						applicationData.put("zipCode", app.getZipCode());
						applicationData.put("city", app.getCity());
						applicationData.put("state", app.getState());
						applicationData.put("isHomeOwner", app.getIsHomeOwner());
						applicationData.put("createdBy", app.getCreatedBy());
						applicationData.put("createdDate", app.getCreatedDate());
						applicationData.put("updatedBy", app.getUpdatedBy());
						applicationData.put("updatedDate", app.getUpdatedDate());
						//applicationData.put("lonetype", app.getLonetype());
						responseMap.put("applicationDetails", applicationData);

						// User Info
						User user = app.getUser();
						if (user != null) {
							Map<String, Object> userData = new LinkedHashMap<>();
							userData.put("userId", user.getUserId());
							userData.put("firstName", user.getFirstName());
							userData.put("lastName", user.getLastName());
							userData.put("email", user.getEmail());
							userData.put("phone", user.getPhone());
							responseMap.put("userDetails", userData);
						}

						// Linked Bank Accounts
						List<LinkBankAccount> bankAccounts = linkedbankaccountRepository
								.findByApplicationDetail_ApplicationNumberAndDelFlag(app.getUserId(), "N");
						if (!bankAccounts.isEmpty()) {
							List<Map<String, Object>> bankList = new ArrayList<>();
							for (LinkBankAccount bank : bankAccounts) {
								Map<String, Object> bankData = new LinkedHashMap<>();
								bankData.put("accountId", bank.getId());
								bankData.put("accountHolderName", bank.getAccountHolderName());
								bankData.put("bankName", bank.getBankName());
								bankData.put("accountNumber", bank.getAccountNumber());
								bankData.put("ifscCode", bank.getIfscCode());
								bankData.put("accountType", bank.getAccountType());
								bankData.put("isAuthorized", bank.getIsAuthorized());
								bankData.put("createdDate", bank.getCreatedDate());
								bankList.add(bankData);
							}
							responseMap.put("linkedBankAccounts", bankList);
						}

						// Document Verifications
						if (user != null) {
							List<DocumentVerification> documents = documentVerificationRepository
									.findByApplicationNumberAndUser_UserIdAndDelFlag(app.getUserId(),
											user.getUserId(), "N");
							if (!documents.isEmpty()) {
								List<Map<String, Object>> docList = new ArrayList<>();
								for (DocumentVerification doc : documents) {
									Map<String, Object> docData = new LinkedHashMap<>();
									docData.put("documentId", doc.getId());
									docData.put("documentType", doc.getDocumentType());
									docData.put("documentNumber", doc.getDocumentNumber());
									docData.put("issueDate", doc.getIssueDate());
									docData.put("expiryDate", doc.getExpiryDate());
									docData.put("issuingAuthority", doc.getIssuingAuthority());
									docData.put("filePath", doc.getFilePath());
									docData.put("consentGiven", doc.getConsentGiven());
									docData.put("createdAt", doc.getCreatedAt());
									docList.add(docData);
								}
								responseMap.put("documentVerifications", docList);
							}
						}

						// Accept Offer
						if (user != null) {
							Optional<AcceptOffer> offerOpt = acceptOfferRepository
									.findByApplicationDetail_ApplicationNumberAndUser_UserIdAndDelFlag(
											app.getUserId(), user.getUserId(), "N");
							offerOpt.ifPresent(offer -> {
								Map<String, Object> offerData = new LinkedHashMap<>();
								offerData.put("offerId", offer.getId());
								offerData.put("loanAmount", offer.getLoanAmount());
								offerData.put("tenureMonths", offer.getTenureMonths());
								offerData.put("interestRate", offer.getInterestRate());
								offerData.put("estimatedEmi", offer.getEstimatedEmi());
								offerData.put("consentGiven", offer.getConsentGiven());
								offerData.put("createdAt", offer.getCreatedAt());
								responseMap.put("acceptOfferDetails", offerData);
							});
						}

						// Review & Agreement
						if (user != null) {
							Optional<ReviewAndAgreement> agreementOpt = reviewAndAgreementRepository
									.findByApplicationNumberAndUserIdAndDelFlag(app.getUserId(),
											user.getUserId(), "N");
							agreementOpt.ifPresent(agreement -> {
								Map<String, Object> agreementData = new LinkedHashMap<>();
								agreementData.put("reviewAgreementId", agreement.getId());
								agreementData.put("infoConfirmed", agreement.getInfoConfirmed());
								agreementData.put("termsAgreed", agreement.getTermsAgreed());
								agreementData.put("identityAuthorized", agreement.getIdentityAuthorized());
								agreementData.put("fullName", agreement.getFullName());
								agreementData.put("signatureType", agreement.getSignatureType());
								agreementData.put("signatureMethod", agreement.getSignatureMethod());
								agreementData.put("signaturePath", agreement.getSignaturePath());
								agreementData.put("createdAt", agreement.getCreatedAt());
								agreementData.put("delFlag", agreement.getDelFlag());
								responseMap.put("reviewAndAgreementDetails", agreementData);
							});
						}

						// Funded Info
						if (user != null) {
							Optional<FundedInfo> fundedOpt = fundedInfoRepository
									.findByApplicationNumberAndUserIdAndDelFlag(app.getUserId(),
											user.getUserId(), "N");
							fundedOpt.ifPresent(funded -> {
								Map<String, Object> fundedData = new LinkedHashMap<>();
								fundedData.put("fundedId", funded.getId());
								fundedData.put("fundingAmount", funded.getFundingAmount());
								fundedData.put("fundingDate", funded.getFundingDate());
								fundedData.put("confirmFunding", funded.getConfirmFunding());
								fundedData.put("createdBy", funded.getCreatedBy());
								fundedData.put("createdDate", funded.getCreatedDate());
								fundedData.put("updatedBy", funded.getUpdatedBy());
								fundedData.put("updatedDate", funded.getUpdatedDate());
								fundedData.put("delFlag", funded.getDelFlag());
								responseMap.put("fundedInfo", fundedData);
							});
						}

						return responseMap;
					}).toList();

			return ResponseEntity.ok(new ApiResponse<>(HttpStatus.OK.value(),
					"All complete application details retrieved successfully", responseList));

		} catch (Exception e) {
			e.printStackTrace();
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
					.body(new ApiResponse<>(HttpStatus.INTERNAL_SERVER_ERROR.value(),
							"Failed to fetch application complete details: " + e.getMessage(), null));
		}
	}

	@GetMapping("/get_fund_details_by_applicationnoly/{applicationNumber}")
	public ResponseEntity<ApiResponse<Map<String, Object>>> getFundedInfoByApplicationNumber(
			@PathVariable String applicationNumber) {
		try {
			// Step 1: Fetch application
			LoanTypeWorkflow application = loanTypeWorkflowRepository
					.findByApplicationNumberAndDelFlag(applicationNumber, "N");

			if (application == null) {
				return ResponseEntity.status(HttpStatus.NOT_FOUND)
						.body(new ApiResponse<>(HttpStatus.NOT_FOUND.value(), "Application not found", null));
			}

			User user = application.getUser();
			if (user == null) {
				return ResponseEntity.status(HttpStatus.NOT_FOUND).body(
						new ApiResponse<>(HttpStatus.NOT_FOUND.value(), "User not found for this application", null));
			}

			// Step 2: Get funded info by application number and user ID
			Optional<FundedInfo> fundedOpt = fundedInfoRepository
					.findByApplicationNumberAndUserIdAndDelFlag(applicationNumber, user.getUserId(), "N");

			if (fundedOpt.isEmpty()) {
				return ResponseEntity.status(HttpStatus.NOT_FOUND)
						.body(new ApiResponse<>(HttpStatus.NOT_FOUND.value(), "Funded info not found", null));
			}

			FundedInfo funded = fundedOpt.get();
			Map<String, Object> fundedData = new LinkedHashMap<>();
			fundedData.put("fundedId", funded.getId());
			fundedData.put("fundingAmount", funded.getFundingAmount());
			fundedData.put("fundingDate", funded.getFundingDate());
			fundedData.put("confirmFunding", funded.getConfirmFunding());
			fundedData.put("createdBy", funded.getCreatedBy());
			fundedData.put("createdDate", funded.getCreatedDate());
			fundedData.put("updatedBy", funded.getUpdatedBy());
			fundedData.put("updatedDate", funded.getUpdatedDate());
			fundedData.put("delFlag", funded.getDelFlag());

			return ResponseEntity.ok(
					new ApiResponse<>(HttpStatus.OK.value(), "Funded information retrieved successfully", fundedData));

		} catch (Exception e) {
			e.printStackTrace();
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(new ApiResponse<>(
					HttpStatus.INTERNAL_SERVER_ERROR.value(), "Failed to fetch funded info: " + e.getMessage(), null));
		}
	}

	@GetMapping("/getApplicationDetails/{applicationNumber}")
	public ResponseEntity<ApiResponse<Map<String, Object>>> getCompleteApplicationDetails(
			@PathVariable String applicationNumber) {
		try {
			
			LoanTypeWorkflow app1 = loanTypeWorkflowRepository.findByApplicationNumberAndDelFlag(applicationNumber,
					"N");
			ApplicationDetail app = applicationDetailRepository.findByUserIdAndDelFlag(app1.getUserId(),
					"N");

			if (app == null) {
				return ResponseEntity.status(HttpStatus.NOT_FOUND)
						.body(new ApiResponse<>(HttpStatus.NOT_FOUND.value(), "Application details not found"));
			}

			Map<String, Object> responseData = new LinkedHashMap<>();

			// Application block
			Map<String, Object> applicationData = new LinkedHashMap<>();
			applicationData.put("applicationId", app.getId());
			//applicationData.put("applicationNumber", app.getApplicationNumber());
			applicationData.put("dateOfBirth", app.getDateOfBirth());
			applicationData.put("monthlyGrossIncome", app.getMonthlyGrossIncome());
			applicationData.put("ssn", app.getSsn());
			applicationData.put("confirmSsn", app.getConfirmSsn());
			applicationData.put("howMuchDoYouNeed", app.getHowMuchDoYouNeed());
			applicationData.put("homeAddress", app.getHomeAddress());
			applicationData.put("homeAddress2", app.getHomeAddress2());
			applicationData.put("zipCode", app.getZipCode());
			applicationData.put("city", app.getCity());
			applicationData.put("state", app.getState());
			applicationData.put("isHomeOwner", app.getIsHomeOwner());
			applicationData.put("createdBy", app.getCreatedBy());
			applicationData.put("createdDate", app.getCreatedDate());
			applicationData.put("updatedBy", app.getUpdatedBy());
			applicationData.put("updatedDate", app.getUpdatedDate());
		//	applicationData.put("lonetype", app.getLonetype());

			responseData.put("applicationDetails", applicationData);

			// User block
			User user = app.getUser();
			if (user != null) {
				Map<String, Object> userData = new LinkedHashMap<>();
				userData.put("userId", user.getUserId());
				userData.put("firstName", user.getFirstName());
				userData.put("lastName", user.getLastName());
				userData.put("email", user.getEmail());
				userData.put("phone", user.getPhone());

				if (user.getRole() != null) {
					userData.put("roleId", user.getRole().getId());
					userData.put("roleName", user.getRole().getRoleName());
				}

				responseData.put("userDetails", userData);

				// Linked Bank Accounts
				List<LinkBankAccount> bankAccounts = linkedbankaccountRepository
						.findByApplicationDetail_ApplicationNumberAndDelFlag(applicationNumber, "N");

				if (!bankAccounts.isEmpty()) {
					List<Map<String, Object>> bankList = new ArrayList<>();
					for (LinkBankAccount bank : bankAccounts) {
						Map<String, Object> bankData = new LinkedHashMap<>();
						bankData.put("accountId", bank.getId());
						bankData.put("accountHolderName", bank.getAccountHolderName());
						bankData.put("bankName", bank.getBankName());
						bankData.put("accountNumber", bank.getAccountNumber());
						bankData.put("ifscCode", bank.getIfscCode());
						bankData.put("accountType", bank.getAccountType());
						bankData.put("isAuthorized", bank.getIsAuthorized());
						bankData.put("createdDate", bank.getCreatedDate());
						bankList.add(bankData);
					}
					responseData.put("linkedBankAccounts", bankList);
				}

				// Document Verifications
				List<DocumentVerification> documents = documentVerificationRepository
						.findByApplicationNumberAndUser_UserIdAndDelFlag(applicationNumber, user.getUserId(), "N");

				if (!documents.isEmpty()) {
					List<Map<String, Object>> docList = new ArrayList<>();
					for (DocumentVerification doc : documents) {
						Map<String, Object> docData = new LinkedHashMap<>();
						docData.put("documentId", doc.getId());
						docData.put("documentType", doc.getDocumentType());
						docData.put("documentNumber", doc.getDocumentNumber());
						docData.put("issueDate", doc.getIssueDate());
						docData.put("expiryDate", doc.getExpiryDate());
						docData.put("issuingAuthority", doc.getIssuingAuthority());
						docData.put("filePath", doc.getFilePath());
						docData.put("consentGiven", doc.getConsentGiven());
						docData.put("createdAt", doc.getCreatedAt());
						docList.add(docData);
					}
					responseData.put("documentVerifications", docList);
				}

				// Accept Offer
				acceptOfferRepository.findByApplicationDetail_ApplicationNumberAndUser_UserIdAndDelFlag(
						applicationNumber, user.getUserId(), "N").ifPresent(offer -> {
							Map<String, Object> offerData = new LinkedHashMap<>();
							offerData.put("offerId", offer.getId());
							offerData.put("loanAmount", offer.getLoanAmount());
							offerData.put("tenureMonths", offer.getTenureMonths());
							offerData.put("interestRate", offer.getInterestRate());
							offerData.put("estimatedEmi", offer.getEstimatedEmi());
							offerData.put("consentGiven", offer.getConsentGiven());
							offerData.put("createdAt", offer.getCreatedAt());
							responseData.put("acceptOffer", offerData);
						});

				// Review & Agreement
				reviewAndAgreementRepository
						.findByApplicationNumberAndUserIdAndDelFlag(applicationNumber, user.getUserId(), "N")
						.ifPresent(agreement -> {
							Map<String, Object> agreementData = new LinkedHashMap<>();
							agreementData.put("reviewAgreementId", agreement.getId());
							agreementData.put("infoConfirmed", agreement.getInfoConfirmed());
							agreementData.put("termsAgreed", agreement.getTermsAgreed());
							agreementData.put("identityAuthorized", agreement.getIdentityAuthorized());
							agreementData.put("fullName", agreement.getFullName());
							agreementData.put("signatureType", agreement.getSignatureType());
							agreementData.put("signatureMethod", agreement.getSignatureMethod());
							agreementData.put("signaturePath", agreement.getSignaturePath());
							agreementData.put("createdAt", agreement.getCreatedAt());
							agreementData.put("delFlag", agreement.getDelFlag());
							responseData.put("reviewAndAgreement", agreementData);
						});

				// ✅ Funded Info
				fundedInfoRepository
						.findByApplicationNumberAndUserIdAndDelFlag(applicationNumber, user.getUserId(), "N")
						.ifPresent(funded -> {
							Map<String, Object> fundedData = new LinkedHashMap<>();
							fundedData.put("fundedId", funded.getId());
							fundedData.put("fundingAmount", funded.getFundingAmount());
							fundedData.put("fundingDate", funded.getFundingDate());
							fundedData.put("confirmFunding", funded.getConfirmFunding());
							fundedData.put("createdBy", funded.getCreatedBy());
							fundedData.put("createdDate", funded.getCreatedDate());
							fundedData.put("updatedBy", funded.getUpdatedBy());
							fundedData.put("updatedDate", funded.getUpdatedDate());
							fundedData.put("delFlag", funded.getDelFlag());
							responseData.put("fundedInfo", fundedData);
						});
			}

			return ResponseEntity.ok(new ApiResponse<>(HttpStatus.OK.value(),
					"Complete application details retrieved successfully", responseData));

		} catch (Exception e) {
			e.printStackTrace();
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(new ApiResponse<>(
					HttpStatus.INTERNAL_SERVER_ERROR.value(), "Error occurred: " + e.getMessage(), null));
		}
	}

	@DeleteMapping("/delete_fundedInfo/{applicationNumber}")
	public ResponseEntity<ApiResponse<String>> deleteFundedInfoByApplicationNumber(
			@PathVariable String applicationNumber) {
		try {
			// Step 1: Validate application
			LoanTypeWorkflow app = loanTypeWorkflowRepository.findByApplicationNumberAndDelFlag(applicationNumber,
					"N");
			if (app == null) {
				return ResponseEntity.status(HttpStatus.NOT_FOUND).body(
						new ApiResponse<>(HttpStatus.NOT_FOUND.value(), "Application not found or already deleted"));
			}

			// Step 2: Get user
			User user = app.getUser();
			if (user == null) {
				return ResponseEntity.status(HttpStatus.NOT_FOUND)
						.body(new ApiResponse<>(HttpStatus.NOT_FOUND.value(), "User not found for this application"));
			}

			// Step 3: Find FundedInfo
			Optional<FundedInfo> fundedOpt = fundedInfoRepository
					.findByApplicationNumberAndUserIdAndDelFlag(applicationNumber, user.getUserId(), "N");

			if (fundedOpt.isEmpty()) {
				return ResponseEntity.status(HttpStatus.NOT_FOUND)
						.body(new ApiResponse<>(HttpStatus.NOT_FOUND.value(), "No funded info found to delete"));
			}

			// Step 4: Soft delete
			FundedInfo funded = fundedOpt.get();
			funded.setDelFlag("Y");
			funded.setUpdatedDate(LocalDateTime.now());
			fundedInfoRepository.save(funded);

			return ResponseEntity.ok(new ApiResponse<>(HttpStatus.OK.value(), "Funded info soft deleted successfully"));

		} catch (Exception e) {
			e.printStackTrace();
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(new ApiResponse<>(
					HttpStatus.INTERNAL_SERVER_ERROR.value(), "Failed to delete funded info: " + e.getMessage()));
		}
	}

	@PutMapping("/update_userdeatils/{userId}")
	public ResponseEntity<ApiResponse<String>> updateUserdeatils(@PathVariable String userId,
			@RequestBody Map<String, String> request) {

		Optional<User> optionalUser = userRepository.findByUserIdAndDelflg(userId, "N");

		if (optionalUser.isEmpty()) {
			return ResponseEntity.status(HttpStatus.NOT_FOUND)
					.body(new ApiResponse<>(HttpStatus.NOT_FOUND.value(), "User not found with ID: " + userId));
		}

		User user = optionalUser.get();

		// Extract fields from request map
		String email = request.get("email");
		String firstName = request.get("firstName");
		String lastName = request.get("lastName");
		String phone = request.get("phone");
		String password = request.get("password");
		String roleIdStr = request.get("roleId");

		if (email != null)
			user.setEmail(email);
		if (firstName != null)
			user.setFirstName(firstName);
		if (lastName != null)
			user.setLastName(lastName);
		if (phone != null)
			user.setPhone(phone);

		if (password != null && !password.isBlank()) {
			user.setPasswordHash(BCrypt.withDefaults().hashToString(12, password.toCharArray()));
		}

		if (roleIdStr != null) {
			try {
				Long roleId = Long.parseLong(roleIdStr);
				Role role = roleRepository.findById(roleId).orElse(null);
				if (role != null) {
					user.setRole(role);
				}
			} catch (NumberFormatException ignored) {
			}
		}

		userRepository.save(user);
		return ResponseEntity.ok(new ApiResponse<>(HttpStatus.OK.value(), "User updated successfully"));
	}

	@DeleteMapping("/delete-userdeatils/{userId}")
	public ResponseEntity<ApiResponse<String>> deleteAccount(@PathVariable String userId) {
		Optional<User> optionalUser = userRepository.findByUserIdAndDelflg(userId, "N");

		if (optionalUser.isEmpty()) {
			return ResponseEntity.status(HttpStatus.NOT_FOUND)
					.body(new ApiResponse<>(HttpStatus.NOT_FOUND.value(), "User not found with ID: " + userId));
		}

		User user = optionalUser.get();
		user.setDelflg("Y");
		user.setActive(false);
		userRepository.save(user);

		return ResponseEntity.ok(new ApiResponse<>(HttpStatus.OK.value(), "User deleted (soft delete) successfully"));
	}
	
	@PostMapping("/add_loan_type")
	public ResponseEntity<ApiResponse<Map<String, Object>>> addLoanType(@RequestBody LoanTypeWorkflow loanTypeRequest) {
	    try {
	        // ? Check if loanType already exists
//	        Optional<LoanTypeWorkflow> existing = loanTypeWorkflowRepository.findByLoanType(loanTypeRequest.getLoanType());
//	        if (existing.isPresent()) {
//	            return ResponseEntity.status(HttpStatus.CONFLICT).body(
//	                new ApiResponse<>(HttpStatus.CONFLICT.value(), "Loan type already exists", null));
//	        }

	        // ? Validate userId
	        String userId = loanTypeRequest.getUserId();
	        if (userId == null || userId.isBlank()) {
	            return ResponseEntity.badRequest().body(
	                new ApiResponse<>(HttpStatus.BAD_REQUEST.value(), "Missing or invalid userId", null));
	        }

	        Optional<User> userOpt = userRepository.findByUserIdAndDelflg(userId, "N");
	        if (userOpt.isEmpty()) {
	            return ResponseEntity.badRequest().body(
	                new ApiResponse<>(HttpStatus.BAD_REQUEST.value(), "User not found for userId: " + userId, null));
	        }

	        // ? Save initial loan type (without app number)
	        LoanTypeWorkflow loanType = new LoanTypeWorkflow();
	        loanType.setLoanType(loanTypeRequest.getLoanType());
	        loanType.setUserId(userId);

	        LoanTypeWorkflow saved = loanTypeWorkflowRepository.save(loanType);

	        
	        String prefix = loanType.getLoanType().replaceAll("[^a-zA-Z]", "").toUpperCase();
	        prefix = prefix.length() >= 3 ? prefix.substring(0, 3) : String.format("%-3s", prefix).replace(' ', 'X');

	        String uid = UUID.randomUUID().toString().replaceAll("-", "").substring(0, 6).toUpperCase();
	        //String applicationNumber = prefix + "-" + uid;
	        String appno = prefix+uid;
	        saved.setApplicationNumber(appno);
	        loanTypeWorkflowRepository.save(saved); // ? Save updated app number

	        // ? Prepare response
	        Map<String, Object> responseData = new LinkedHashMap<>();
	        responseData.put("loanTypeId", saved.getId());
	        responseData.put("loanType", saved.getLoanType());
	        responseData.put("applicationNumber", saved.getApplicationNumber());
	        responseData.put("userId", saved.getUserId());

	        return ResponseEntity.ok(new ApiResponse<>(HttpStatus.OK.value(),
	                "Loan type added successfully with application number", responseData));

	    } catch (Exception e) {
	        e.printStackTrace();
	        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(
	            new ApiResponse<>(HttpStatus.INTERNAL_SERVER_ERROR.value(),
	                    "Failed to add loan type: " + e.getMessage(), null));
	    }
	}
}