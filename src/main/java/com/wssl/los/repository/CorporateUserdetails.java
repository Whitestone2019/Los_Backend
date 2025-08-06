package com.wssl.los.repository;

import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.wssl.los.model.CorporateApplicationDetail;

@Repository
public interface CorporateUserdetails extends JpaRepository<CorporateApplicationDetail, Long> {

	CorporateApplicationDetail save(CorporateApplicationDetail applicationDetail);

	Optional<CorporateApplicationDetail> findById(Long id);

	CorporateApplicationDetail findByCorporateApplicationNumberAndDelFlag(String corporateApplicationNumber,
			String delFlag);

	List<CorporateApplicationDetail> findByDelFlag(String string);

}

