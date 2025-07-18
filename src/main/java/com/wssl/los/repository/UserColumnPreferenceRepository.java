package com.wssl.los.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserColumnPreferenceRepository extends JpaRepository<UserColumnPreference, Long> {
   
    Optional<UserColumnPreference> findByColumnName(String columnName);

}
