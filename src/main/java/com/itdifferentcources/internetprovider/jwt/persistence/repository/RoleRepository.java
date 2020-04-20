package com.itdifferentcources.internetprovider.jwt.persistence.repository;

import com.itdifferentcources.internetprovider.jwt.persistence.entity.Role;
import com.itdifferentcources.internetprovider.jwt.persistence.entity.Role.RoleType;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface RoleRepository extends JpaRepository<Role, Long> {
    Optional<Role> findByName(RoleType name);
}
