package com.wssl.los.model;

import java.time.LocalDateTime;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

@Entity
@Table(name = "roles")
public class Role {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "role_name")
    private String roleName;

    private String description;

    @Column(name = "rcre_time")
    private LocalDateTime rcreTime;

    @Column(name = "updt_time")
    private LocalDateTime updtTime;

    @Column(name = "delflg", length = 1)
    private String delflg = "N"; // Default to 'N' (Not deleted)

    // Getters and setters
    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getRoleName() {
        return roleName;
    }

    public void setRoleName(String roleName) {
        this.roleName = roleName;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
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
