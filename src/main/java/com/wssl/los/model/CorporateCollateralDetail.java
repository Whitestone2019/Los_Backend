package com.wssl.los.model;



import jakarta.persistence.*;
import java.time.LocalDate;


@Entity
@Table(name = "corporate_collateral_detail")
public class CorporateCollateralDetail {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    
    @ManyToOne
    @JoinColumn(name = "corporate_application_id", referencedColumnName = "id")
    private CorporateApplicationDetail corporateApplicationDetail;

    
    @ManyToOne
    @JoinColumn(name = "user_id", referencedColumnName = "user_id")
    private User user;

    @Column(name = "collateral_type")
    private String collateralType;

    @Column(name = "property_type")
    private String propertyType;

    @Column(name = "is_primary_residential")
    private Boolean isPrimaryResidential;

    @Column(name = "property_street_address")
    private String propertyStreetAddress;

    @Column(name = "zip_code")
    private String zipCode;

    @Column(name = "state")
    private String state;

    @Column(name = "city")
    private String city;

    @Column(name = "approved_value")
    private Double approvedValue;

    @Column(name = "debt")
    private Double debt;

    @Column(name = "validation_date")
    private LocalDate validationDate;

    @Column(name = "assigned_ltv")
    private Double assignedLtv;

    @Column(name = "perfection_status")
    private String perfectionStatus;

    @Column(name = "is_released")
    private Boolean isReleased;

    @Column(name = "country")
    private String country;

    @Column(name = "del_flag")
    private String delFlag;

    @Column(name = "created_by")
    private String createdBy;

    @Column(name = "created_date")
    private LocalDate createdDate;

    @Column(name = "updated_by")
    private String updatedBy;

    @Column(name = "updated_date")
    private LocalDate updatedDate;

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

    public String getCollateralType() {
        return collateralType;
    }

    public void setCollateralType(String collateralType) {
        this.collateralType = collateralType;
    }

    public String getPropertyType() {
        return propertyType;
    }

    public void setPropertyType(String propertyType) {
        this.propertyType = propertyType;
    }

    public Boolean getIsPrimaryResidential() {
        return isPrimaryResidential;
    }

    public void setIsPrimaryResidential(Boolean isPrimaryResidential) {
        this.isPrimaryResidential = isPrimaryResidential;
    }

    public String getPropertyStreetAddress() {
        return propertyStreetAddress;
    }

    public void setPropertyStreetAddress(String propertyStreetAddress) {
        this.propertyStreetAddress = propertyStreetAddress;
    }

    public String getZipCode() {
        return zipCode;
    }

    public void setZipCode(String zipCode) {
        this.zipCode = zipCode;
    }

    public String getState() {
        return state;
    }

    public void setState(String state) {
        this.state = state;
    }

    public String getCity() {
        return city;
    }

    public void setCity(String city) {
        this.city = city;
    }

    public Double getApprovedValue() {
        return approvedValue;
    }

    public void setApprovedValue(Double approvedValue) {
        this.approvedValue = approvedValue;
    }

    public Double getDebt() {
        return debt;
    }

    public void setDebt(Double debt) {
        this.debt = debt;
    }

    public LocalDate getValidationDate() {
        return validationDate;
    }

    public void setValidationDate(LocalDate validationDate) {
        this.validationDate = validationDate;
    }

    public Double getAssignedLtv() {
        return assignedLtv;
    }

    public void setAssignedLtv(Double assignedLtv) {
        this.assignedLtv = assignedLtv;
    }

    public String getPerfectionStatus() {
        return perfectionStatus;
    }

    public void setPerfectionStatus(String perfectionStatus) {
        this.perfectionStatus = perfectionStatus;
    }

    public Boolean getIsReleased() {
        return isReleased;
    }

    public void setIsReleased(Boolean isReleased) {
        this.isReleased = isReleased;
    }

    public String getCountry() {
        return country;
    }

    public void setCountry(String country) {
        this.country = country;
    }

    public String getDelFlag() {
        return delFlag;
    }

    public void setDelFlag(String delFlag) {
        this.delFlag = delFlag;
    }

    public String getCreatedBy() {
        return createdBy;
    }

    public void setCreatedBy(String createdBy) {
        this.createdBy = createdBy;
    }

    public LocalDate getCreatedDate() {
        return createdDate;
    }

    public void setCreatedDate(LocalDate createdDate) {
        this.createdDate = createdDate;
    }

    public String getUpdatedBy() {
        return updatedBy;
    }

    public void setUpdatedBy(String updatedBy) {
        this.updatedBy = updatedBy;
    }

    public LocalDate getUpdatedDate() {
        return updatedDate;
    }

    public void setUpdatedDate(LocalDate updatedDate) {
        this.updatedDate = updatedDate;
    }
}


