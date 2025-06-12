package com.wssl.los.model;

import java.time.LocalDateTime;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

@Entity
@Table(name = "organizations")
public class Organization {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String name;

    private String address;

    private String logo;

    @Column(name = "rcre_time")
    private LocalDateTime rcreTime;

    @Column(name = "updt_time")
    private LocalDateTime updtTime;

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
    public String getAddress() { return address; }
    public void setAddress(String address) { this.address = address; }
    public String getLogo() { return logo; }
    public void setLogo(String logo) { this.logo = logo; }
    public LocalDateTime getRcreTime() { return rcreTime; }
    public void setRcreTime(LocalDateTime rcreTime) { this.rcreTime = rcreTime; }
    public LocalDateTime getUpdtTime() { return updtTime; }
    public void setUpdtTime(LocalDateTime updtTime) { this.updtTime = updtTime; }
}