package com.wssl.los.controller;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.hibernate.internal.build.AllowSysOut;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
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

import com.wssl.los.model.MenuPermission;
import com.wssl.los.model.Organization;
import com.wssl.los.model.Role;
import com.wssl.los.model.User;
import com.wssl.los.repository.MenuPermissionRepository;
import com.wssl.los.repository.OrganizationRepository;
import com.wssl.los.repository.RoleRepository;
import com.wssl.los.repository.UserRepository;
import com.wssl.los.util.JwtUtil;

import at.favre.lib.crypto.bcrypt.BCrypt;
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
	private MenuPermissionRepository menuPermissionRepository;

	@Autowired
	private JwtUtil jwtUtil;

	@PostMapping("/login")
	public ResponseEntity<?> login(@RequestBody Map<String, String> request) {
		String username = request.get("username");
		String password = request.get("password");
		System.out.println(username);
		// Find user by username
		User user = userRepository.findByUsername(username);

		// Verify credentials
		if (user != null && BCrypt.verifyer().verify(password.toCharArray(), user.getPasswordHash()).verified) {
			// Generate JWT token
			String token = jwtUtil.generateToken(user.getUsername());

			// Prepare response map with token and role
			Map<String, Object> response = new HashMap<>();
			response.put("token", token);
			response.put("role", user.getRole() != null ? user.getRole().getRoleName() : null);

			return ResponseEntity.ok(response);
		}

		return ResponseEntity.status(401).body("Invalid credentials");
	}
	
	@GetMapping("/users")
	public ResponseEntity<List<User>> getAllUser() {
		return ResponseEntity.ok(userRepository.findAll());
	}

	@PostMapping("/register")
	public ResponseEntity<?> register(@RequestBody Map<String, String> request) {
		// Extract fields from request body
		String username = request.get("username");
		String password = request.get("password");
		String email = request.get("email");
		String fullName = request.get("fullName");
		String roleIdStr = request.get("roleId");
		String department = request.get("department");

		// Validate required fields
		if (username == null || password == null || email == null || roleIdStr == null) {
			return ResponseEntity.badRequest().body("Missing required fields: username, password, email, or roleId");
		}

		// Check if username or email already exists
		if (userRepository.findByUsername(username) != null) {
			return ResponseEntity.badRequest().body("Username already exists");
		}
		if (userRepository.findByEmail(email) != null) {
			return ResponseEntity.badRequest().body("Email already exists");
		}

		// Parse roleId
		Long roleId;
		try {
			roleId = Long.parseLong(roleIdStr);
		} catch (NumberFormatException e) {
			return ResponseEntity.badRequest().body("Invalid roleId format");
		}

		// Fetch role
		Role role = roleRepository.findById(roleId).orElseThrow(() -> new RuntimeException("Role not found"));

		// Create and populate User entity
		User user = new User();
		user.setUsername(username);
		user.setPasswordHash(BCrypt.withDefaults().hashToString(12, password.toCharArray()));
		user.setEmail(email);
		user.setFullName(fullName);
		user.setRole(role);

		// Save user
		userRepository.save(user);

		// Return success message
		return ResponseEntity.ok("Registration successful");
	}

	@PostMapping("/set-password")
	@PreAuthorize("isAuthenticated()")
	public ResponseEntity<?> setPassword(@RequestBody Map<String, String> request) {
		String username = request.get("username");
		String newPassword = request.get("newPassword");
		User user = userRepository.findByUsername(username);
		if (user == null) {
			return ResponseEntity.badRequest().body("User not found");
		}
		user.setPasswordHash(BCrypt.withDefaults().hashToString(12, newPassword.toCharArray()));
		userRepository.save(user);
		return ResponseEntity.ok("Password updated successfully");
	}

	@PostMapping("/reset-password")
	public ResponseEntity<?> resetPassword(@RequestBody Map<String, String> request) {
		String email = request.get("email");
		String newPassword = request.get("newPassword");
		User user = userRepository.findByEmail(email);
		if (user == null) {
			return ResponseEntity.badRequest().body("Email not found");
		}
		// Simplified: In production, send a reset token via email
		user.setPasswordHash(BCrypt.withDefaults().hashToString(12, newPassword.toCharArray()));
		userRepository.save(user);
		return ResponseEntity.ok("Password reset successfully");
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

	@DeleteMapping("/roles/{id}")
	public ResponseEntity<?> deleteRole(@PathVariable Long id) {
		Role role = roleRepository.findById(id).orElseThrow(() -> new RuntimeException("Role not found"));
		roleRepository.delete(role);
		return ResponseEntity.ok("Role deleted successfully");
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
				.orElseThrow(() -> new RuntimeException("Organization not found"));
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

	@PostMapping("/menu-permissions")
	public ResponseEntity<?> createMenuPermission(@RequestBody @Valid MenuPermission permission) {
		Role role = roleRepository.findById(permission.getRoleId())
				.orElseThrow(() -> new RuntimeException("Role not found"));
		permission.setRcreTime(LocalDateTime.now());
		menuPermissionRepository.save(permission);
		return ResponseEntity.ok(permission);
	}

	@PutMapping("/menu-permissions/{id}")
	public ResponseEntity<?> updateMenuPermission(@PathVariable Long id,
			@RequestBody @Valid MenuPermission permission) {
		MenuPermission existingPermission = menuPermissionRepository.findById(id)
				.orElseThrow(() -> new RuntimeException("Menu permission not found"));
		Role role = roleRepository.findById(permission.getRoleId())
				.orElseThrow(() -> new RuntimeException("Role not found"));
		existingPermission.setRoleId(permission.getRoleId());
		existingPermission.setMenuName(permission.getMenuName());
		existingPermission.setReadPermission(permission.isReadPermission());
		existingPermission.setWritePermission(permission.isWritePermission());
		existingPermission.setViewPermission(permission.isViewPermission());
		existingPermission.setAllPermission(permission.isAllPermission());
		existingPermission.setUpdtTime(LocalDateTime.now());
		menuPermissionRepository.save(existingPermission);
		return ResponseEntity.ok(existingPermission);
	}

	@DeleteMapping("/menu-permissions/{id}")
	public ResponseEntity<?> deleteMenuPermission(@PathVariable Long id) {
		MenuPermission permission = menuPermissionRepository.findById(id)
				.orElseThrow(() -> new RuntimeException("Menu permission not found"));
		menuPermissionRepository.delete(permission);
		return ResponseEntity.ok("Menu permission deleted successfully");
	}

	@GetMapping("/menu-permissions")
	public ResponseEntity<List<MenuPermission>> getAllMenuPermissions() {
		return ResponseEntity.ok(menuPermissionRepository.findAll());
	}
}