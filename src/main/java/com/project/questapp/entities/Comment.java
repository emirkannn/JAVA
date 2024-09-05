package com.project.questapp.entities;

import java.util.Date;

import org.hibernate.annotations.OnDelete;
import org.hibernate.annotations.OnDeleteAction;

import com.fasterxml.jackson.annotation.JsonIgnore;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.Lob;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import jakarta.persistence.Temporal;
import jakarta.persistence.TemporalType;
import lombok.Data;

@Entity
@Table(name = "comment")
@Data
public class Comment {
	
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
	
	@Lob
	@Column(columnDefinition = "text") // stringi text olarak aslın varchar olarak almasın
	String text;
	
	@Temporal(TemporalType.TIMESTAMP)
	Date createDate;
	
}
