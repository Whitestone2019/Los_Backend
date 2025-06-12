package com.wssl.los.model;

import java.time.LocalDateTime;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

@Entity
@Table(name = "menu_permissions")
public class MenuPermission {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "role_id")
    private Long roleId;

    @Column(name = "menu_name")
    private String menuName;

    @Column(name = "read_permission")
    private boolean readPermission;

    @Column(name = "write_permission")
    private boolean writePermission;

    @Column(name = "view_permission")
    private boolean viewPermission;

    @Column(name = "all_permission")
    private boolean allPermission;

    @Column(name = "rcre_time")
    private LocalDateTime rcreTime;

    @Column(name = "updt_time")
    private LocalDateTime updtTime;

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    public Long getRoleId() { return roleId; }
    public void setRoleId(Long roleId) { this.roleId = roleId; }
    public String getMenuName() { return menuName; }
    public void setMenuName(String menuName) { this.menuName = menuName; }
    public boolean isReadPermission() { return readPermission; }
    public void setReadPermission(boolean readPermission) { this.readPermission = readPermission; }
    public boolean isWritePermission() { return writePermission; }
    public void setWritePermission(boolean writePermission) { this.writePermission = writePermission; }
    public boolean isViewPermission() { return viewPermission; }
    public void setViewPermission(boolean viewPermission) { this.viewPermission = viewPermission; }
    public boolean isAllPermission() { return allPermission; }
    public void setAllPermission(boolean allPermission) { this.allPermission = allPermission; }
    public LocalDateTime getRcreTime() { return rcreTime; }
    public void setRcreTime(LocalDateTime rcreTime) { this.rcreTime = rcreTime; }
    public LocalDateTime getUpdtTime() { return updtTime; }
    public void setUpdtTime(LocalDateTime updtTime) { this.updtTime = updtTime; }
}