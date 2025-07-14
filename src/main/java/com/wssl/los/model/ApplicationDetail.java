package com.wssl.los.model;
 
import java.time.LocalDateTime;
import java.util.Date;
 
import jakarta.persistence.*;
 
@Entity
@Table(name = "application_detail")
public class ApplicationDetail {
 
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
 
    // ✅ Store userId in DB and allow setting from controller
    @Column(name = "user_id")
    private String userId;
 
    // ✅ Maintain relationship with User entity (read-only)
    @ManyToOne
    @JoinColumn(name = "user_id", referencedColumnName = "user_id", insertable = false, updatable = false)
    private User user;
 
    @Temporal(TemporalType.DATE)
    private Date dateOfBirth;
 
    private Double monthlyGrossIncome;
    private String ssn;
    private String confirmSsn;
    private Long howMuchDoYouNeed;
    private String homeAddress;
    private String homeAddress2;
    private Long zipCode;
    private String city;
    private String state;
    private Boolean isHomeOwner;
 
    private String createdBy;
 
    @Column(name = "created_date")
    private LocalDateTime createdDate;
 
    private String updatedBy;
 
    @Column(name = "updated_date")
    private LocalDateTime updatedDate;
 
    private String delFlag;

	public Long getId() {
		return id;
	}

	public void setId(Long id) {
		this.id = id;
	}

	public String getUserId() {
		return userId;
	}

	public void setUserId(String userId) {
		this.userId = userId;
	}

	public User getUser() {
		return user;
	}

	public void setUser(User user) {
		this.user = user;
	}

	public Date getDateOfBirth() {
		return dateOfBirth;
	}

	public void setDateOfBirth(Date dateOfBirth) {
		this.dateOfBirth = dateOfBirth;
	}

	public Double getMonthlyGrossIncome() {
		return monthlyGrossIncome;
	}

	public void setMonthlyGrossIncome(Double monthlyGrossIncome) {
		this.monthlyGrossIncome = monthlyGrossIncome;
	}

	public String getSsn() {
		return ssn;
	}

	public void setSsn(String ssn) {
		this.ssn = ssn;
	}

	public String getConfirmSsn() {
		return confirmSsn;
	}

	public void setConfirmSsn(String confirmSsn) {
		this.confirmSsn = confirmSsn;
	}

	public Long getHowMuchDoYouNeed() {
		return howMuchDoYouNeed;
	}

	public void setHowMuchDoYouNeed(Long howMuchDoYouNeed) {
		this.howMuchDoYouNeed = howMuchDoYouNeed;
	}

	public String getHomeAddress() {
		return homeAddress;
	}

	public void setHomeAddress(String homeAddress) {
		this.homeAddress = homeAddress;
	}

	public String getHomeAddress2() {
		return homeAddress2;
	}

	public void setHomeAddress2(String homeAddress2) {
		this.homeAddress2 = homeAddress2;
	}

	public Long getZipCode() {
		return zipCode;
	}

	public void setZipCode(Long zipCode) {
		this.zipCode = zipCode;
	}

	public String getCity() {
		return city;
	}

	public void setCity(String city) {
		this.city = city;
	}

	public String getState() {
		return state;
	}

	public void setState(String state) {
		this.state = state;
	}

	public Boolean getIsHomeOwner() {
		return isHomeOwner;
	}

	public void setIsHomeOwner(Boolean isHomeOwner) {
		this.isHomeOwner = isHomeOwner;
	}

	public String getCreatedBy() {
		return createdBy;
	}

	public void setCreatedBy(String createdBy) {
		this.createdBy = createdBy;
	}

	public LocalDateTime getCreatedDate() {
		return createdDate;
	}

	public void setCreatedDate(LocalDateTime createdDate) {
		this.createdDate = createdDate;
	}

	public String getUpdatedBy() {
		return updatedBy;
	}

	public void setUpdatedBy(String updatedBy) {
		this.updatedBy = updatedBy;
	}

	public LocalDateTime getUpdatedDate() {
		return updatedDate;
	}

	public void setUpdatedDate(LocalDateTime updatedDate) {
		this.updatedDate = updatedDate;
	}

	public String getDelFlag() {
		return delFlag;
	}

	public void setDelFlag(String delFlag) {
		this.delFlag = delFlag;
	}
 
 
    // ===================== GETTERS & SETTERS ======================
 

 
   
}
 