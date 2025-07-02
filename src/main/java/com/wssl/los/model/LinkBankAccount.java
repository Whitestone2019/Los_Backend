package com.wssl.los.model;

import java.time.LocalDateTime;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Transient;

@Entity
public class LinkBankAccount {
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id;

	// Link to User
	@ManyToOne
	@JoinColumn(name = "user_id", referencedColumnName = "user_id")
	private User user;

	// Link to ApplicationDetail
	@ManyToOne
	@JoinColumn(name = "application_id", referencedColumnName = "id")
	private ApplicationDetail applicationDetail;

	@Column(name = "account_holder_name", nullable = false)
	private String accountHolderName;

	@Column(name = "bank_name", nullable = false)
	private String bankName;

	@Column(name = "account_number", nullable = false)
	private String accountNumber;

	@Transient
	private String confirmAccountNumber; // Only for UI form validation

	@Column(name = "ifsc_code", nullable = false)
	private String ifscCode;

	@Column(name = "account_type", nullable = false)
	private String accountType;

	@Column(name = "is_authorized")
	private Boolean isAuthorized;

	@Column(name = "created_date")
	private LocalDateTime createdDate;

	@Column(name = "del_flag")
	private String delFlag;

	public Long getId() {
		return id;
	}

	public void setId(Long id) {
		this.id = id;
	}

	public User getUser() {
		return user;
	}

	public void setUser(User user) {
		this.user = user;
	}

	public ApplicationDetail getApplicationDetail() {
		return applicationDetail;
	}

	public void setApplicationDetail(ApplicationDetail applicationDetail) {
		this.applicationDetail = applicationDetail;
	}

	public String getAccountHolderName() {
		return accountHolderName;
	}

	public void setAccountHolderName(String accountHolderName) {
		this.accountHolderName = accountHolderName;
	}

	public String getBankName() {
		return bankName;
	}

	public void setBankName(String bankName) {
		this.bankName = bankName;
	}

	public String getAccountNumber() {
		return accountNumber;
	}

	public void setAccountNumber(String accountNumber) {
		this.accountNumber = accountNumber;
	}

	public String getConfirmAccountNumber() {
		return confirmAccountNumber;
	}

	public void setConfirmAccountNumber(String confirmAccountNumber) {
		this.confirmAccountNumber = confirmAccountNumber;
	}

	public String getIfscCode() {
		return ifscCode;
	}

	public void setIfscCode(String ifscCode) {
		this.ifscCode = ifscCode;
	}

	public String getAccountType() {
		return accountType;
	}

	public void setAccountType(String accountType) {
		this.accountType = accountType;
	}

	public Boolean getIsAuthorized() {
		return isAuthorized;
	}

	public void setIsAuthorized(Boolean isAuthorized) {
		this.isAuthorized = isAuthorized;
	}

	public LocalDateTime getCreatedDate() {
		return createdDate;
	}

	public void setCreatedDate(LocalDateTime createdDate) {
		this.createdDate = createdDate;
	}

	public String getDelFlag() {
		return delFlag;
	}

	public void setDelFlag(String delFlag) {
		this.delFlag = delFlag;
	}

	// Getters and Setters

	
}