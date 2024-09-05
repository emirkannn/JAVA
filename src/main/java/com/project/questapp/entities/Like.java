package com.project.questapp.entities;

import org.hibernate.annotations.OnDelete;
import org.hibernate.annotations.OnDeleteAction;

import com.fasterxml.jackson.annotation.JsonIgnore;

import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;

import lombok.Data;

@Entity
@Table(name = "p_like")
@Data
public class Like {
	
	@Id
	@GeneratedValue( strategy = GenerationType.IDENTITY )
	Long id;
	@ManyToOne(fetch = FetchType.LAZY)// post öğesi geldiğinde içinde user gelmesin diye
	@JoinColumn(name = "post_id",nullable = false)
	@OnDelete(action = OnDeleteAction.CASCADE)// User silindiğinde post da sil
	@JsonIgnore
	Post post;
	
	@ManyToOne(fetch = FetchType.LAZY)// post öğesi geldiğinde içinde user gelmesin diye
	@JoinColumn(name = "user_id",nullable = false)
	@OnDelete(action = OnDeleteAction.CASCADE)// User silindiğinde post da sil
	@JsonIgnore
	User user;
	
	
}
