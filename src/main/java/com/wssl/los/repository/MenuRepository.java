package com.wssl.los.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import com.wssl.los.model.Menu;

public interface MenuRepository extends JpaRepository<Menu, Long> {
    List<Menu> findByParentIsNull(); // for top-level menus
    
    @Query("SELECT DISTINCT m FROM Menu m LEFT JOIN FETCH m.subMenus ORDER BY m.id")
    List<Menu> findAllWithSubMenus();

}
