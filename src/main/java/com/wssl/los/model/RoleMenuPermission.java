package com.wssl.los.model;

import jakarta.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "role_menu_permission")
public class RoleMenuPermission {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "role_id")
    private Long roleId;

    @Column(name = "menu_id")
    private Long menuId;

    @Column(name = "can_read")
    private Boolean canRead = false;

    @Column(name = "can_write")
    private Boolean canWrite = false;

    @Column(name = "can_all")
    private Boolean canAll = false;

    @Column(name = "rcre_time")
    private LocalDateTime rcreTime = LocalDateTime.now();

    @Column(name = "updt_time")
    private LocalDateTime updtTime = LocalDateTime.now();

    @Column(name = "delflg", length = 1)
    private String delflg = "N";

	public Long getId() {
		return id;
	}

	public void setId(Long id) {
		this.id = id;
	}

	public Long getRoleId() {
		return roleId;
	}

	public void setRoleId(Long roleId) {
		this.roleId = roleId;
	}

	public Long getMenuId() {
		return menuId;
	}

	public void setMenuId(Long menuId) {
		this.menuId = menuId;
	}

	public Boolean getCanRead() {
		return canRead;
	}

	public void setCanRead(Boolean canRead) {
		this.canRead = canRead;
	}

	public Boolean getCanWrite() {
		return canWrite;
	}

	public void setCanWrite(Boolean canWrite) {
		this.canWrite = canWrite;
	}

	public Boolean getCanAll() {
		return canAll;
	}

	public void setCanAll(Boolean canAll) {
		this.canAll = canAll;
	}

	public LocalDateTime getRcreTime() {
		return rcreTime;
	}

	public void setRcreTime(LocalDateTime rcreTime) {
		this.rcreTime = rcreTime;
	}

	public LocalDateTime getUpdtTime() {
		return updtTime;
	}

	public void setUpdtTime(LocalDateTime updtTime) {
		this.updtTime = updtTime;
	}

	public String getDelflg() {
		return delflg;
	}

	public void setDelflg(String delflg) {
		this.delflg = delflg;
	}

  
}
