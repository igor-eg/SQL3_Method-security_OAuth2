
package ru.netology.sqlHib.service;

import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import ru.netology.sqlHib.entity.City;
import ru.netology.sqlHib.entity.Person;
import ru.netology.sqlHib.repository.CityRepository;
import ru.netology.sqlHib.repository.PersonRepository;

import java.util.List;

@Service
public class SqlService {

    private final CityRepository cityRepository;
    private final PersonRepository personRepository;

    public SqlService(CityRepository cityRepository, PersonRepository personRepository) {
        this.cityRepository = cityRepository;
        this.personRepository = personRepository;
    }

    public List<City> readAllCityThanOrderByName() {
        return cityRepository.findAll(Sort.by("name").ascending());
    }

    List<Person> findByCityName(String cityName) {
        return null;
    }


    public List<Person> readAllPersonThanOrderByAge() {
        return personRepository.findAll(Sort.by("personalData.age").ascending());
    }


    public City readCityByName(String name) throws Exception {
            City probablyCity = cityRepository.findCityByName(name);
            if (probablyCity != null) {
                return probablyCity;
            } else throw new Exception();
        }

    // Создание и сохранение города в Базе данных
    public City createCity(String name) throws Exception {
        City probablyCity = cityRepository.findCityByName(name);
        if (probablyCity == null) {
            return cityRepository.save(City.builder().name(name).build());
        } else throw new Exception();
    }

}