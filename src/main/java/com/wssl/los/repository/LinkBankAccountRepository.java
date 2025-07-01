package com.wssl.los.repository;
 
import java.util.List;
import java.util.Optional;
 
import org.springframework.data.jpa.repository.JpaRepository;
 
import com.wssl.los.model.LinkBankAccount;
 
public interface LinkBankAccountRepository extends JpaRepository<LinkBankAccount, Long>{
 
	Optional<LinkBankAccount> findByUser_UserIdAndApplicationDetail_ApplicationNumber(String userId,
			String applicationNumber);
 
	List<LinkBankAccount> findByApplicationDetail_ApplicationNumberAndDelFlag(String applicationnumber, String string);
 
}