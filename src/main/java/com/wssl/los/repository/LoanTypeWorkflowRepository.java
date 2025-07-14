package com.wssl.los.repository;

import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.wssl.los.model.LoanType;

public interface LoanTypeWorkflowRepository extends JpaRepository<LoanTypeWorkflow, Long> {
    Optional<LoanTypeWorkflow> findByLoanType(String loanType);

    List<LoanTypeWorkflow> findByUserId(String userId);

	LoanTypeWorkflow findByApplicationNumberAndDelFlag(String applicationNumber, String string);

	List<LoanTypeWorkflow> findByUserIdAndDelFlag(String userId, String string);

	
}
