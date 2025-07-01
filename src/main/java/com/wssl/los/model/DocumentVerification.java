package com.wssl.los.model;
 
import java.time.LocalDate;
import java.time.LocalDateTime;
 
import jakarta.persistence.*;
 
@Entity
public class DocumentVerification {
 
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    @Column(name = "user_reference_id")
    private String userId;
 
    // Reference to ApplicationDetail
    private String applicationNumber;
 
    // Reference to User entity
    @ManyToOne
    @JoinColumn(name = "user_id", nullable = false)
    private User user;
 
    private String documentType;
 
    @Column(nullable = false)
    private String documentNumber;
 
    private LocalDate issueDate;
 
    private LocalDate expiryDate;
 
    private String issuingAuthority;
 
    // Stores the file path of the uploaded document
    private String filePath;
 
    // Whether user consented to verification
    private Boolean consentGiven;
 
    // Soft delete flag ("N" = active, "Y" = deleted)
    @Column(length = 1)
    private String delFlag = "N";
 
    private LocalDateTime createdAt;
 
    // Constructor
    public DocumentVerification() {
        this.createdAt = LocalDateTime.now();
    }
 
    // ------------------- Getters and Setters -------------------
 
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
 
	public String getApplicationNumber() {
        return applicationNumber;
    }
 
    public void setApplicationNumber(String applicationNumber) {
        this.applicationNumber = applicationNumber;
    }
 
    public User getUser() {
        return user;
    }
 
    public void setUser(User user) {
        this.user = user;
    }
 
    public String getDocumentType() {
        return documentType;
    }
 
    public void setDocumentType(String documentType) {
        this.documentType = documentType;
    }
 
    public String getDocumentNumber() {
        return documentNumber;
    }
 
    public void setDocumentNumber(String documentNumber) {
        this.documentNumber = documentNumber;
    }
 
    public LocalDate getIssueDate() {
        return issueDate;
    }
 
    public void setIssueDate(LocalDate issueDate) {
        this.issueDate = issueDate;
    }
 
    public LocalDate getExpiryDate() {
        return expiryDate;
    }
 
    public void setExpiryDate(LocalDate expiryDate) {
        this.expiryDate = expiryDate;
    }
 
    public String getIssuingAuthority() {
        return issuingAuthority;
    }
 
    public void setIssuingAuthority(String issuingAuthority) {
        this.issuingAuthority = issuingAuthority;
    }
 
    public String getFilePath() {
        return filePath;
    }
 
    public void setFilePath(String filePath) {
        this.filePath = filePath;
    }
 
    public Boolean getConsentGiven() {
        return consentGiven;
    }
 
    public void setConsentGiven(Boolean consentGiven) {
        this.consentGiven = consentGiven;
    }
 
    public String getDelFlag() {
        return delFlag;
    }
 
    public void setDelFlag(String delFlag) {
        this.delFlag = delFlag;
    }
 
    public LocalDateTime getCreatedAt() {
        return createdAt;
    }
 
    public void setCreatedAt(LocalDateTime createdAt) {
        this.createdAt = createdAt;
    }
}