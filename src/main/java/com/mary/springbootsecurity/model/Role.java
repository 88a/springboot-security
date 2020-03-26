package com.mary.springbootsecurity.model;

import lombok.Data;

import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Table;

@Entity
@Table(name = "roles")
@Data
public class Role {
    @Id
    private Integer id;
    private String name;
}
