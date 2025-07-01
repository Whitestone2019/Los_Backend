package com.wssl.los.repository;
 
import java.util.List;
import java.util.Optional;
 
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
 
import com.wssl.los.model.DocumentVerification;
@Repository
public interface DocumentverificationRepository extends JpaRepository<DocumentVerification, Long> {

 
	Optional<DocumentVerification> findByApplicationNumberAndUser_UserIdAndDocumentNumberAndDelFlag(
			String applicationNumber, String userId, String documentNumber, String string);
 
	List<DocumentVerification> findByApplicationNumberAndUser_UserIdAndDelFlag(String applicationnumber, String userId,
			String string);

}