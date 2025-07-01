package com.wssl.los.repository;
 
import java.util.Optional;
 
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
 
import com.wssl.los.model.AcceptOffer;
 
@Repository
public interface AcceptOfferRepository extends JpaRepository<AcceptOffer, Long>{
 
	Optional<AcceptOffer> findByApplicationDetail_ApplicationNumberAndUser_UserIdAndDelFlag(String applicationnumber,
			String userId, String string);
 
	Optional<AcceptOffer> findByApplicationDetail_IdAndUser_UserIdAndDelFlag(Long id, String userId, String string);

 
 
}