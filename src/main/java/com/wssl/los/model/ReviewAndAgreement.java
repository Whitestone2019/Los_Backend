package com.wssl.los.model;
 
import jakarta.persistence.*;

import java.time.LocalDateTime;

import com.wssl.los.repository.LoanTypeWorkflow;
 
@Entity

@Table(name = "review_and_agreement")

public class ReviewAndAgreement {
 
    @Id

    @GeneratedValue(strategy = GenerationType.IDENTITY)

    private Long id;
 
    // Application link

    @ManyToOne

    @JoinColumn(name = "application_id", nullable = false)

    private LoanTypeWorkflow applicationDetail;
 
    @Column(name = "application_number", nullable = false)

    private String applicationNumber;
 
    // Store userId directly as String

    @Column(name = "user_id", nullable = false)

    private String userId;
 
    // Agreement checkboxes

    @Column(name = "info_confirmed")

    private Boolean infoConfirmed;
 
    @Column(name = "terms_agreed")

    private Boolean termsAgreed;
 
    @Column(name = "identity_authorized")

    private Boolean identityAuthorized;
 
    // Signature

    @Column(name = "full_name")

    private String fullName;
 
    @Column(name = "signature_type")

    private String signatureType;
 
    @Column(name = "signature_method")

    private String signatureMethod;
 
    @Column(name = "signature_path")

    private String signaturePath;
 
    // Audit fields

    @Column(name = "created_at", nullable = false)

    private LocalDateTime createdAt = LocalDateTime.now();
 
    @Column(name = "del_flag", nullable = false, length = 1)

    private String delFlag = "N";

	public Long getId() {
		return id;
	}

	public void setId(Long id) {
		this.id = id;
	}

	public LoanTypeWorkflow getApplicationDetail() {
		return applicationDetail;
	}

	public void setApplicationDetail(LoanTypeWorkflow applicationDetail) {
		this.applicationDetail = applicationDetail;
	}

	public String getApplicationNumber() {
		return applicationNumber;
	}

	public void setApplicationNumber(String applicationNumber) {
		this.applicationNumber = applicationNumber;
	}

	public String getUserId() {
		return userId;
	}

	public void setUserId(String userId) {
		this.userId = userId;
	}

	public Boolean getInfoConfirmed() {
		return infoConfirmed;
	}

	public void setInfoConfirmed(Boolean infoConfirmed) {
		this.infoConfirmed = infoConfirmed;
	}

	public Boolean getTermsAgreed() {
		return termsAgreed;
	}

	public void setTermsAgreed(Boolean termsAgreed) {
		this.termsAgreed = termsAgreed;
	}

	public Boolean getIdentityAuthorized() {
		return identityAuthorized;
	}

	public void setIdentityAuthorized(Boolean identityAuthorized) {
		this.identityAuthorized = identityAuthorized;
	}

	public String getFullName() {
		return fullName;
	}

	public void setFullName(String fullName) {
		this.fullName = fullName;
	}

	public String getSignatureType() {
		return signatureType;
	}

	public void setSignatureType(String signatureType) {
		this.signatureType = signatureType;
	}

	public String getSignatureMethod() {
		return signatureMethod;
	}

	public void setSignatureMethod(String signatureMethod) {
		this.signatureMethod = signatureMethod;
	}

	public String getSignaturePath() {
		return signaturePath;
	}

	public void setSignaturePath(String signaturePath) {
		this.signaturePath = signaturePath;
	}

	public LocalDateTime getCreatedAt() {
		return createdAt;
	}

	public void setCreatedAt(LocalDateTime createdAt) {
		this.createdAt = createdAt;
	}

	public String getDelFlag() {
		return delFlag;
	}

	public void setDelFlag(String delFlag) {
		this.delFlag = delFlag;
	}
 
    // ---------- Getters & Setters ----------
 
  
}

 