package com.wssl.los.repository;
 
import java.util.Optional;
 
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
 
import com.wssl.los.model.User;
 
// Repository Interfaces
@Repository
public interface UserRepository extends JpaRepository<User, Long> {
 
	User findByUserId(String userId);
 
	User findByEmail(String email);
 
	Optional<User> findByUserIdAndDelflg(String userId, String delflg);
 
	
}