package com.wssl.los.model;

import jakarta.persistence.*;

@Entity
@Table(name = "loan_type_master")
public class LoanType {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "loan_type", unique = true, nullable = false)
    private String loanType;

    @Column(name = "description", nullable = false)
    private String description;

    @Lob
    @Column(name = "approval_setup", columnDefinition = "TEXT")
    private String approvalSetup; // stores JSON string

    // Getters & Setters
    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getLoanType() {
        return loanType;
    }

    public void setLoanType(String loanType) {
        this.loanType = loanType;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getApprovalSetup() {
        return approvalSetup;
    }

    public void setApprovalSetup(String approvalSetup) {
        this.approvalSetup = approvalSetup;
    }
}
