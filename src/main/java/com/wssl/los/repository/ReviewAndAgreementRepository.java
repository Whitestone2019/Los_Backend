package com.wssl.los.repository;
 
import java.util.Optional;
 
import org.springframework.data.jpa.repository.JpaRepository;

import org.springframework.stereotype.Repository;
 
import com.wssl.los.model.ReviewAndAgreement;

@Repository
 
public interface ReviewAndAgreementRepository extends JpaRepository<ReviewAndAgreement, Long> {
 
	

	Optional<ReviewAndAgreement> findByApplicationNumberAndUserIdAndDelFlag(String applicationNumber, String userId, String delFlag);
 
 
	
 
}

 