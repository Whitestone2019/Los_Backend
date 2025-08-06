package com.wssl.los.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.wssl.los.model.CorporateApplicationDetail;
import com.wssl.los.model.CorporateBusinessDetail;
@Repository
public interface CorporateBusinessDetailRepositoy extends JpaRepository<CorporateBusinessDetail, Long>{

	Optional<CorporateBusinessDetail> findByCorporateApplicationNumberAndUser_UserIdAndDelFlag(
		    String corporateApplicationNumber, String userId, String delFlag);

	CorporateApplicationDetail findByCorporateApplicationNumberAndDelFlag(String corpAppNumber, String string);
		
	}
