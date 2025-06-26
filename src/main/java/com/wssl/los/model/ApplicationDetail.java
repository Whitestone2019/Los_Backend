package com.wssl.los.model;
import java.time.LocalDateTime;
import java.util.Date;
 
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Temporal;
import jakarta.persistence.TemporalType;
@Entity
public class ApplicationDetail {
	@Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
	private String userid;
    @ManyToOne
    @JoinColumn(name = "user_id", referencedColumnName = "user_id")
    private User user;
    @Column(name = "application_number")
	private String applicationNumber;
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
    @Temporal(TemporalType.TIMESTAMP)
	private LocalDateTime createdDate;
    private String updatedBy;
    @Temporal(TemporalType.TIMESTAMP)
	private Date updatedDate;
    private String delFlag ;
//getter and setters//
		public Long getId() {
			return id;
		}
		public void setId(Long id) {
			this.id = id;
		}
		public String getUserid() {
			return userid;
		}
 
		public void setUserid(String userid) {
			this.userid = userid;
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
	    public void setCreatedDate(LocalDateTime localDateTime) {
	        this.createdDate = localDateTime;
	    }
	    public String getUpdatedBy() {
	        return updatedBy;
	    }
	    public void setUpdatedBy(String updatedBy) {
	        this.updatedBy = updatedBy;
	    }
	    public Date getUpdatedDate() {
	        return updatedDate;
	    }
	    public void setUpdatedDate(Date updatedDate) {
	        this.updatedDate = updatedDate;
	    }
	    public String getDelFlag() {
	        return delFlag;
	    }
	    public void setDelFlag(String delFlag) {
	        this.delFlag = delFlag;
	    }
 
		public User getUser() {
			return user;
		}
 
		public void setUser(User user) {
			this.user = user;
		}
 
		
 
		public String getApplicationnumber() {
			return applicationNumber;
		}
 
		public void setApplicationnumber(String application_number) {
			this.applicationNumber= application_number;
		}



}