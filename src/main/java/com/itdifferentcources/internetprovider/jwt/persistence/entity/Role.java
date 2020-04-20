package com.itdifferentcources.internetprovider.jwt.persistence.entity;

import javax.persistence.Entity;
import javax.persistence.EnumType;
import javax.persistence.Enumerated;
import javax.persistence.Table;
import lombok.AccessLevel;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;

@Data
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Entity
@Table(name = "roles")
public class Role extends BaseEntity implements GrantedAuthority {

    @Enumerated(EnumType.STRING)
    private RoleType name;

    @Override
    public String getAuthority() {
        return name.name();
    }

    public enum RoleType{
        ROLE_CUSTOMER, ROLE_ADMIN, ROLE_MODERATOR
    }

}
