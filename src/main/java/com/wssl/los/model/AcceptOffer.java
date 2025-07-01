package com.wssl.los.model;
 
import java.math.BigDecimal;

import java.time.LocalDateTime;
 
import jakarta.persistence.*;
 
@Entity

public class AcceptOffer {
 
    @Id

    @GeneratedValue(strategy = GenerationType.IDENTITY)

    private Long id;
 
    @ManyToOne

    @JoinColumn(name = "application_id")

    private ApplicationDetail applicationDetail;
 
    @Column(name = "application_number", nullable = false)

    private String applicationNumber;
 
    // Relationship with User

    @ManyToOne

    @JoinColumn(name = "user_id", nullable = false)

    private User user;
 
    @Column(name = "loan_amount", nullable = false)

    private BigDecimal loanAmount;
 
    @Column(name = "tenure_months", nullable = false)

    private Integer tenureMonths;
 
    @Column(name = "interest_rate", nullable = false)

    private Double interestRate;
 
    @Column(name = "estimated_emi", nullable = false)

    private BigDecimal estimatedEmi;
 
    @Column(name = "consent_given", nullable = false)

    private Boolean consentGiven;
 
    @Column(name = "del_flag", nullable = false)

    private String delFlag = "N";
 
    @Column(name = "created_at", nullable = false)

    private LocalDateTime createdAt = LocalDateTime.now();
 
    // ------------------- Getters and Setters -------------------
 
    public Long getId() {

        return id;

    }
 
    public void setId(Long id) {

        this.id = id;

    }
 
    public String getApplicationNumber() {

        return applicationNumber;

    }
 
    public void setApplicationNumber(String applicationNumber) {

        this.applicationNumber = applicationNumber;

    }
 
    public ApplicationDetail getApplicationDetail() {

        return applicationDetail;

    }
 
    public void setApplicationDetail(ApplicationDetail applicationDetail) {

        this.applicationDetail = applicationDetail;

    }
 
    public User getUser() {

        return user;

    }
 
    public void setUser(User user) {

        this.user = user;

    }
 
    public BigDecimal getLoanAmount() {

        return loanAmount;

    }
 
    public void setLoanAmount(BigDecimal loanAmount) {

        this.loanAmount = loanAmount;

    }
 
    public Integer getTenureMonths() {

        return tenureMonths;

    }
 
    public void setTenureMonths(Integer tenureMonths) {

        this.tenureMonths = tenureMonths;

    }
 
    public Double getInterestRate() {

        return interestRate;

    }
 
    public void setInterestRate(Double interestRate) {

        this.interestRate = interestRate;

    }
 
    public BigDecimal getEstimatedEmi() {

        return estimatedEmi;

    }
 
    public void setEstimatedEmi(BigDecimal estimatedEmi) {

        this.estimatedEmi = estimatedEmi;

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

 