package com.wssl.los.model;
 
import jakarta.persistence.*;

import java.time.LocalDate;

import java.time.LocalDateTime;
 
@Entity

@Table(name = "funded_info")

public class FundedInfo {
 
    @Id

    @GeneratedValue(strategy = GenerationType.IDENTITY)

    private Long id;
 
    // Link to ApplicationDetail

    @ManyToOne

    @JoinColumn(name = "application_id", nullable = false)

    private ApplicationDetail applicationDetail;
 
    @Column(name = "application_number", nullable = false)

    private String applicationNumber;
 
    @Column(name = "user_id", nullable = false)

    private String userId;
 
    @Column(name = "funding_amount")

    private Double fundingAmount;
 
    @Column(name = "funding_date")

    private LocalDate fundingDate;
 
    @Column(name = "confirm_funding")

    private Boolean confirmFunding;
 
    @Column(name = "created_by")

    private String createdBy;
 
    @Column(name = "created_date")

    private LocalDateTime createdDate;
 
    @Column(name = "updated_by")

    private String updatedBy;
 
    @Column(name = "updated_date")

    private LocalDateTime updatedDate;
 
    @Column(name = "del_flag", nullable = false, length = 1)

    private String delFlag = "N";
 
    // ---------- Getters & Setters ----------
 
    public Long getId() {

        return id;

    }
 
    public void setId(Long id) {

        this.id = id;

    }
 
    public ApplicationDetail getApplicationDetail() {

        return applicationDetail;

    }
 
    public void setApplicationDetail(ApplicationDetail applicationDetail) {

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
 
    public Double getFundingAmount() {

        return fundingAmount;

    }
 
    public void setFundingAmount(Double fundingAmount) {

        this.fundingAmount = fundingAmount;

    }
 
    public LocalDate getFundingDate() {

        return fundingDate;

    }
 
    public void setFundingDate(LocalDate fundingDate) {

        this.fundingDate = fundingDate;

    }
 
    public Boolean getConfirmFunding() {

        return confirmFunding;

    }
 
    public void setConfirmFunding(Boolean confirmFunding) {

        this.confirmFunding = confirmFunding;

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

 