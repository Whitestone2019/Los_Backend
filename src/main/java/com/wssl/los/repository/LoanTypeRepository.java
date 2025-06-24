package com.wssl.los.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.wssl.los.model.LoanType;

public interface LoanTypeRepository extends JpaRepository<LoanType, Long> {
    Optional<LoanType> findByLoanType(String loanType);
}
