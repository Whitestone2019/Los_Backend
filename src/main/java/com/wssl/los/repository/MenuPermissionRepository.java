package com.wssl.los.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.wssl.los.model.MenuPermission;

@Repository
public interface MenuPermissionRepository extends JpaRepository<MenuPermission, Long> {
	}