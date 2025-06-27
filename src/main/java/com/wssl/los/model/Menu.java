package com.wssl.los.model;

import java.util.ArrayList;
import java.util.List;

import com.fasterxml.jackson.annotation.JsonIgnore;

import jakarta.persistence.CascadeType;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.OneToMany;
import jakarta.persistence.Table;

@Entity
@Table(name = "menu")
public class Menu {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "menu_name")
    private String menuName;

    private String url;

    private String icon;

    @Column(name = "delflg", length = 1)
    private String delflg = "N";
    
    @Column(name = "type", length = 20)
    private String type;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "parent_id")
    @JsonIgnore 
    private Menu parent;

    @OneToMany(mappedBy = "parent", cascade = CascadeType.ALL)
    private List<Menu> subMenus = new ArrayList<>();

	public Long getId() {
		return id;
	}

	public void setId(Long id) {
		this.id = id;
	}

	public String getMenuName() {
		return menuName;
	}

	public void setMenuName(String menuName) {
		this.menuName = menuName;
	}

	public String getUrl() {
		return url;
	}

	public void setUrl(String url) {
		this.url = url;
	}

	public String getIcon() {
		return icon;
	}

	public void setIcon(String icon) {
		this.icon = icon;
	}

	public String getDelflg() {
		return delflg;
	}

	public void setDelflg(String delflg) {
		this.delflg = delflg;
	}

	public String getType() {
		return type;
	}

	public void setType(String type) {
		this.type = type;
	}

	public Menu getParent() {
		return parent;
	}

	public void setParent(Menu parent) {
		this.parent = parent;
	}

	public List<Menu> getSubMenus() {
		return subMenus;
	}

	public void setSubMenus(List<Menu> subMenus) {
		this.subMenus = subMenus;
	}

	public Menu(Long id, String menuName, String url, String icon, String delflg, String type, Menu parent,
			List<Menu> subMenus) {
		super();
		this.id = id;
		this.menuName = menuName;
		this.url = url;
		this.icon = icon;
		this.delflg = delflg;
		this.type = type;
		this.parent = parent;
		this.subMenus = subMenus;
	}

	@Override
	public String toString() {
		return "Menu [id=" + id + ", menuName=" + menuName + ", url=" + url + ", icon=" + icon + ", delflg=" + delflg
				+ ", type=" + type + ", parent=" + parent + ", subMenus=" + subMenus + ", getId()=" + getId()
				+ ", getMenuName()=" + getMenuName() + ", getUrl()=" + getUrl() + ", getIcon()=" + getIcon()
				+ ", getDelflg()=" + getDelflg() + ", getType()=" + getType() + ", getParent()=" + getParent()
				+ ", getSubMenus()=" + getSubMenus() + ", getClass()=" + getClass() + ", hashCode()=" + hashCode()
				+ ", toString()=" + super.toString() + "]";
	}

	public Menu() {
		super();
		// TODO Auto-generated constructor stub
	}

	
    
}
