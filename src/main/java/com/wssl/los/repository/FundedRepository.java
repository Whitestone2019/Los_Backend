package com.wssl.los.repository;
 
import java.util.Optional;
 
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
 
import com.wssl.los.model.FundedInfo;
 
@Repository
public interface FundedRepository extends JpaRepository<FundedInfo, Long>{
 
	Optional<FundedInfo> findByApplicationNumberAndUserIdAndDelFlag(String applicationNumber, String userId,
			String delFlag);
 
}