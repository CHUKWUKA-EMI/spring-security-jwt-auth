package com.chukwuka.authproject.repositories;

import com.chukwuka.authproject.models.ERole;
import com.chukwuka.authproject.models.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RoleRepository extends JpaRepository<Role,Long> {
    Optional<Role> findByName(ERole name);
}
