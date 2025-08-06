package com.wssl.los.model;

import jakarta.persistence.*;
import java.time.LocalDate;
import java.time.LocalDateTime;

@Entity
@Table(name = "corporate_owner_detail")
public class CorporateOwnerDetail {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    // Link to the application
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "corporate_application_id", referencedColumnName = "id", nullable = false)
    private CorporateApplicationDetail corporateApplicationDetail;

    // Link to the user (if applicable)
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", referencedColumnName = "user_id")
    private User user;

    @Column(name = "owner_first_name", nullable = false)
    private String ownerFirstName;

    @Column(name = "owner_last_name", nullable = false)
    private String ownerLastName;

    @Column(name = "date_of_birth", nullable = false)
    private LocalDate dateOfBirth;

    @Column(name = "ownership_percentage", nullable = false)
    private Double ownershipPercentage;

    @Column(name = "address_line1", nullable = false)
    private String addressLine1;

    @Column(name = "address_line2")
    private String addressLine2;

    @Column(name = "zip_code", nullable = false)
    private String zipCode;

    @Column(name = "city", nullable = false)
    private String city;

    @Column(name = "state", nullable = false)
    private String state;

    @Column(name = "country")
    private String country;

    @Column(name = "credit_report_authorized")
    private Boolean creditReportAuthorized;

    @Column(name = "application_consent_given")
    private Boolean applicationConsentGiven;

    @Column(name = "del_flag", length = 1)
    private String delFlag = "N";

    @Column(name = "created_date")
    private LocalDateTime createdDate;

    @Column(name = "created_by")
    private String createdBy;

    @Column(name = "updated_date")
    private LocalDateTime updatedDate;

    @Column(name = "updated_by")
    private String updatedBy;

    // 🟩 Getters and Setters

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public CorporateApplicationDetail getCorporateApplicationDetail() {
        return corporateApplicationDetail;
    }

    public void setCorporateApplicationDetail(CorporateApplicationDetail corporateApplicationDetail) {
        this.corporateApplicationDetail = corporateApplicationDetail;
    }

    public User getUser() {
        return user;
    }

    public void setUser(User user) {
        this.user = user;
    }

    public String getOwnerFirstName() {
        return ownerFirstName;
    }

    public void setOwnerFirstName(String ownerFirstName) {
        this.ownerFirstName = ownerFirstName;
    }

    public String getOwnerLastName() {
        return ownerLastName;
    }

    public void setOwnerLastName(String ownerLastName) {
        this.ownerLastName = ownerLastName;
    }

    public LocalDate getDateOfBirth() {
        return dateOfBirth;
    }

    public void setDateOfBirth(LocalDate dateOfBirth) {
        this.dateOfBirth = dateOfBirth;
    }

    public Double getOwnershipPercentage() {
        return ownershipPercentage;
    }

    public void setOwnershipPercentage(Double ownershipPercentage) {
        this.ownershipPercentage = ownershipPercentage;
    }

    public String getAddressLine1() {
        return addressLine1;
    }

    public void setAddressLine1(String addressLine1) {
        this.addressLine1 = addressLine1;
    }

    public String getAddressLine2() {
        return addressLine2;
    }

    public void setAddressLine2(String addressLine2) {
        this.addressLine2 = addressLine2;
    }

    public String getZipCode() {
        return zipCode;
    }

    public void setZipCode(String zipCode) {
        this.zipCode = zipCode;
    }

    public String getCity() {
        return city;
    }

    public void setCity(String city) {
        this.city = city;
    }

    public String getState() {
        return state;
    }

    public void setState(String state) {
        this.state = state;
    }

    public String getCountry() {
        return country;
    }

    public void setCountry(String country) {
        this.country = country;
    }

    public Boolean getCreditReportAuthorized() {
        return creditReportAuthorized;
    }

    public void setCreditReportAuthorized(Boolean creditReportAuthorized) {
        this.creditReportAuthorized = creditReportAuthorized;
    }

    public Boolean getApplicationConsentGiven() {
        return applicationConsentGiven;
    }

    public void setApplicationConsentGiven(Object object) {
        this.applicationConsentGiven = (Boolean) object;
    }

    public String getDelFlag() {
        return delFlag;
    }

    public void setDelFlag(String delFlag) {
        this.delFlag = delFlag;
    }

    public LocalDateTime getCreatedDate() {
        return createdDate;
    }

    public void setCreatedDate(LocalDateTime localDateTime) {
        this.createdDate = localDateTime;
    }

    public String getCreatedBy() {
        return createdBy;
    }

    public void setCreatedBy(String createdBy) {
        this.createdBy = createdBy;
    }

    public LocalDateTime getUpdatedDate() {
        return updatedDate;
    }

    public void setUpdatedDate(LocalDateTime localDateTime) {
        this.updatedDate = localDateTime;
    }

    public String getUpdatedBy() {
        return updatedBy;
    }

    public void setUpdatedBy(String updatedBy) {
        this.updatedBy = updatedBy;
    }

	

	
	
}
