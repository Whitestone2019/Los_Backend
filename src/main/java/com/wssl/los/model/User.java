package com.wssl.los.model;

import jakarta.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "users")
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id") // Primary key
    private Long id;

    @Column(name = "user_id", unique = true)
    private String userId; // Business code like USR001

    @Column(name = "first_name")
    private String firstName;

    @Column(name = "last_name")
    private String lastName;

    @Transient // Will not be stored in DB, used for input only
    private String password;

    @Column(name = "password_hash")
    private String passwordHash;

    private String email;

    private String phone;

    private boolean active;

    @Column(name = "rcreation_time")
    private LocalDateTime rcreationTime;

    @Column(name = "rcreation_user")
    private String rcreationUser;

    @Column(name = "delflg", length = 1)
    private String delflg = "N"; // 'Y' = deleted, 'N' = active (default)

    @ManyToOne
    @JoinColumn(name = "role_id") // Foreign key
    private Role role;

	public Long getId() {
		return id;
	}

	public void setId(Long id) {
		this.id = id;
	}

	public String getUserId() {
		return userId;
	}

	public void setUserId(String userId) {
		this.userId = userId;
	}

	public String getFirstName() {
		return firstName;
	}

	public void setFirstName(String firstName) {
		this.firstName = firstName;
	}

	public String getLastName() {
		return lastName;
	}

	public void setLastName(String lastName) {
		this.lastName = lastName;
	}

	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}

	public String getPasswordHash() {
		return passwordHash;
	}

	public void setPasswordHash(String passwordHash) {
		this.passwordHash = passwordHash;
	}

	public String getEmail() {
		return email;
	}

	public void setEmail(String email) {
		this.email = email;
	}

	public String getPhone() {
		return phone;
	}

	public void setPhone(String phone) {
		this.phone = phone;
	}

	public boolean isActive() {
		return active;
	}

	public void setActive(boolean active) {
		this.active = active;
	}

	public LocalDateTime getRcreationTime() {
		return rcreationTime;
	}

	public void setRcreationTime(LocalDateTime rcreationTime) {
		this.rcreationTime = rcreationTime;
	}

	public String getRcreationUser() {
		return rcreationUser;
	}

	public void setRcreationUser(String rcreationUser) {
		this.rcreationUser = rcreationUser;
	}

	public String getDelflg() {
		return delflg;
	}

	public void setDelflg(String delflg) {
		this.delflg = delflg;
	}

	public Role getRole() {
		return role;
	}

	public void setRole(Role role) {
		this.role = role;
	}

    // ===== Getters and Setters =====

    
}
