package com.company.readinglist.repository;

import com.company.readinglist.model.Reader;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface ReaderRepository extends JpaRepository<Reader,String> {
    Optional<Reader> findByUsername(String username);
}
