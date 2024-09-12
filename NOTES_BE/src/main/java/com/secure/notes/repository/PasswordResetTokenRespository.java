package com.secure.notes.repository;

import com.secure.notes.model.PasswordResetToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface PasswordResetTokenRespository extends JpaRepository<PasswordResetToken, Long> {

}
