package com.wssl.los.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.wssl.los.model.CorporateApplicationDetail;
import com.wssl.los.model.CorporateOwnerDetail;
import com.wssl.los.model.Otp;

public interface CorporateOwner extends JpaRepository<CorporateOwnerDetail, Long> {

	Optional<CorporateOwnerDetail> findFirstByCorporateApplicationDetailAndDelFlagOrderByCreatedDateAsc(
			CorporateApplicationDetail corpApp, String string);

	Optional<CorporateOwnerDetail> findByCorporateApplicationDetail_CorporateApplicationNumberAndUser_UserIdAndDelFlag(
			String corpAppNumber, String userId, String string);

}
