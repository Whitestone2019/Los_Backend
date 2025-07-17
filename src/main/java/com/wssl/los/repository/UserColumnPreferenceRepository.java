package com.wssl.los.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserColumnPreferenceRepository extends JpaRepository<UserColumnPreference, Long> {
    List<UserColumnPreference> findByUserId(String userId);
}
