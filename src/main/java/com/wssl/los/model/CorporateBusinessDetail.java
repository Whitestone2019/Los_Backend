package com.wssl.los.model;


import jakarta.persistence.*;
import java.time.LocalDate;
import java.time.LocalDateTime;

@Entity
@Table(name = "corporate_business_detail")
public class CorporateBusinessDetail {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "corporate_application_number", nullable = false)
    private String corporateApplicationNumber;

    @ManyToOne
    @JoinColumn(name = "corporate_application_number", referencedColumnName = "corporate_application_number", insertable = false, updatable = false)
    private CorporateApplicationDetail corporateApplicationDetail;

    @ManyToOne
    @JoinColumn(name = "user_id", referencedColumnName = "user_id")
    private User user;

    @Column(name = "dba", nullable = false)
    private String dba;

    @Column(name = "ssn_itin", nullable = false, length = 9)
    private String ssnItin;

    @Column(name = "business_address1", nullable = false)
    private String businessAddress1;

    @Column(name = "business_address2")
    private String businessAddress2;

    @Column(name = "zip_code", nullable = false)
    private String zipCode;

    @Column(name = "city", nullable = false)
    private String city;

    @Column(name = "state", nullable = false)
    private String state;

    @Column(name = "revenue", nullable = false)
    private Double revenue;

    @Column(name = "time_in_business", nullable = false)
    private String timeInBusiness;

    @Column(name = "business_start_date")
    private LocalDate businessStartDate;

    @Column(name = "type_of_business", nullable = false)
    private String typeOfBusiness;

    @Column(name = "industry", nullable = false)
    private String industry;

    @Column(name = "tax_id", nullable = false)
    private String taxId;

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

    // ======= Getters and Setters =======

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getCorporateApplicationNumber() {
        return corporateApplicationNumber;
    }

    public void setCorporateApplicationNumber(String corporateApplicationNumber) {
        this.corporateApplicationNumber = corporateApplicationNumber;
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

    public String getDba() {
        return dba;
    }

    public void setDba(String dba) {
        this.dba = dba;
    }

    public String getSsnItin() {
        return ssnItin;
    }

    public void setSsnItin(String ssnItin) {
        this.ssnItin = ssnItin;
    }

    public String getBusinessAddress1() {
        return businessAddress1;
    }

    public void setBusinessAddress1(String businessAddress1) {
        this.businessAddress1 = businessAddress1;
    }

    public String getBusinessAddress2() {
        return businessAddress2;
    }

    public void setBusinessAddress2(String businessAddress2) {
        this.businessAddress2 = businessAddress2;
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

    public Double getRevenue() {
        return revenue;
    }

    public void setRevenue(Double revenue) {
        this.revenue = revenue;
    }

    public String getTimeInBusiness() {
        return timeInBusiness;
    }

    public void setTimeInBusiness(String timeInBusiness) {
        this.timeInBusiness = timeInBusiness;
    }

    public LocalDate getBusinessStartDate() {
        return businessStartDate;
    }

    public void setBusinessStartDate(LocalDate businessStartDate) {
        this.businessStartDate = businessStartDate;
    }

    public String getTypeOfBusiness() {
        return typeOfBusiness;
    }

    public void setTypeOfBusiness(String typeOfBusiness) {
        this.typeOfBusiness = typeOfBusiness;
    }

    public String getIndustry() {
        return industry;
    }

    public void setIndustry(String industry) {
        this.industry = industry;
    }

    public String getTaxId() {
        return taxId;
    }

    public void setTaxId(String taxId) {
        this.taxId = taxId;
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

