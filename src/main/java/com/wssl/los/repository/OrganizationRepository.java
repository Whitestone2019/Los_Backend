package com.wssl.los.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.wssl.los.model.Organization;

@Repository
public interface OrganizationRepository extends JpaRepository<Organization, Long> {
	}