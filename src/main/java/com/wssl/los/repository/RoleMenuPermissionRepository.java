package com.wssl.los.repository;

import java.util.List;
import java.util.Map;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import com.wssl.los.model.RoleMenuPermission;

public interface RoleMenuPermissionRepository extends JpaRepository<RoleMenuPermission, Long> {
	@Query(value = "SELECT rmp.id AS id, " +
            "rmp.role_id AS roleId, " +
            "rmp.menu_id AS menuId, " +
            "m.menu_name AS menuName, " +
            "rmp.can_read AS canRead, " +
            "rmp.can_write AS canWrite, " +
            "rmp.can_all AS canAll, " +
            "rmp.rcre_time AS rcreTime, " +
            "rmp.updt_time AS updtTime " +
            "FROM role_menu_permission rmp " +
            "JOIN menu m ON rmp.menu_id = m.id " +
            "WHERE rmp.role_id = :roleId AND rmp.delflg = 'N' AND m.delflg = 'N'", nativeQuery = true)
List<Map<String, Object>> getPermissionsWithMenuName(@Param("roleId") Long roleId);

}
