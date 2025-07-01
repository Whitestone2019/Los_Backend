package com.wssl.los.repository;

import java.util.Optional;
 
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import com.wssl.los.model.ApplicationDetail;
import com.wssl.los.model.DocumentVerification;
@Repository
public interface ApplicationDetailRepository extends JpaRepository<ApplicationDetail, Long> {
	ApplicationDetail save(ApplicationDetail userDetails);
	ApplicationDetail findByApplicationNumberAndDelFlag(String applicationNumber, String delFlag);
	long countByDelFlag(String string);


}