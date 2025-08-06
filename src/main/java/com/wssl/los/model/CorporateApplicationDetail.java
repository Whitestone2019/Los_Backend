package com.wssl.los.model;


import jakarta.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "corporate_application_detail")
public class CorporateApplicationDetail {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "corporate_id", nullable = false)
    private String corporateId;

    @Column(name = "corporate_application_number", nullable = false, unique = true)
    private String corporateApplicationNumber;

    @Column(name = "company_legal_name", nullable = false)
    private String companyLegalName;

    @Column(name = "amount_requested", nullable = false)
    private Double amountRequested;

    @Column(name = "contact_first_name", nullable = false)
    private String contactFirstName;

    @Column(name = "contact_last_name", nullable = false)
    private String contactLastName;

    @Column(name = "contact_email_id", nullable = false)
    private String contactEmailId;

    @Column(name = "contact_phone", nullable = false)
    private String contactPhone;

    // Store userId directly
    @Column(name = "user_id")
    private String userId;

    // Read-only relationship with User entity
    @ManyToOne
    @JoinColumn(name = "user_id", referencedColumnName = "user_id", insertable = false, updatable = false)
    private User user;

    @Column(name = "created_by")
    private String createdBy;

    @Column(name = "created_date")
    private LocalDateTime createdDate;

    @Column(name = "updated_by")
    private String updatedBy;

    @Column(name = "updated_date")
    private LocalDateTime updatedDate;

    @Column(name = "del_flag", nullable = false)
    private String delFlag = "N";

    // ===================== GETTERS & SETTERS ======================

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getCorporateId() {
        return corporateId;
    }

    public void setCorporateId(String corporateId) {
        this.corporateId = corporateId;
    }

    public String getCorporateApplicationNumber() {
        return corporateApplicationNumber;
    }

    public void setCorporateApplicationNumber(String corporateApplicationNumber) {
        this.corporateApplicationNumber = corporateApplicationNumber;
    }

    public String getCompanyLegalName() {
        return companyLegalName;
    }

    public void setCompanyLegalName(String companyLegalName) {
        this.companyLegalName = companyLegalName;
    }

    public Double getAmountRequested() {
        return amountRequested;
    }

    public void setAmountRequested(Double amountRequested) {
        this.amountRequested = amountRequested;
    }

    public String getContactFirstName() {
        return contactFirstName;
    }

    public void setContactFirstName(String contactFirstName) {
        this.contactFirstName = contactFirstName;
    }

    public String getContactLastName() {
        return contactLastName;
    }

    public void setContactLastName(String contactLastName) {
        this.contactLastName = contactLastName;
    }

    public String getContactEmailId() {
        return contactEmailId;
    }

    public void setContactEmailId(String contactEmailId) {
        this.contactEmailId = contactEmailId;
    }

    public String getContactPhone() {
        return contactPhone;
    }

    public void setContactPhone(String contactPhone) {
        this.contactPhone = contactPhone;
    }

    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }

    public User getUser() {
        return user;
    }

    public void setUser(User user) {
        this.user = user;
    }

    public String getCreatedBy() {
        return createdBy;
    }

    public void setCreatedBy(String createdBy) {
        this.createdBy = createdBy;
    }

    public LocalDateTime getCreatedDate() {
        return createdDate;
    }

    public void setCreatedDate(LocalDateTime createdDate) {
        this.createdDate = createdDate;
    }

    public String getUpdatedBy() {
        return updatedBy;
    }

    public void setUpdatedBy(String updatedBy) {
        this.updatedBy = updatedBy;
    }

    public LocalDateTime getUpdatedDate() {
        return updatedDate;
    }

    public void setUpdatedDate(LocalDateTime updatedDate) {
        this.updatedDate = updatedDate;
    }

    public String getDelFlag() {
        return delFlag;
    }

    public void setDelFlag(String delFlag) {
        this.delFlag = delFlag;
    }
}
