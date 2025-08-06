package com.wssl.los.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;


import com.wssl.los.model.CorporateCollateralDetail;

public interface CorporatecollateralRepo extends JpaRepository<CorporateCollateralDetail, Long> {

	Optional<CorporateCollateralDetail> findByCorporateApplicationDetail_CorporateApplicationNumberAndUser_UserIdAndDelFlag(
			String corpAppNumber, String userId, String delFlag);

}
