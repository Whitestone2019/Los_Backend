package com.wssl.los.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.wssl.los.model.ApprovalProcessFlow;

public interface ApprovalProcessFlowRepository extends JpaRepository<ApprovalProcessFlow, Long> {
    Optional<ApprovalProcessFlow> findByLoanType(String loanType);
}
