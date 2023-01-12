package ru.netology.sqlHib.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import ru.netology.sqlHib.entity.City;
import ru.netology.sqlHib.entity.Person;
import ru.netology.sqlHib.entity.PersonalData;


import java.util.List;
@Repository
public interface PersonRepository extends JpaRepository<Person, PersonalData> {

}