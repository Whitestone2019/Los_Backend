package com.wssl.los.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;

import com.wssl.los.model.Menu;

public interface MenuRepository extends JpaRepository<Menu, Long> {
    List<Menu> findByParentIsNull(); // for top-level menus
}
