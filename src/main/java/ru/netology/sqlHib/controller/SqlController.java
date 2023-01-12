
package ru.netology.sqlHib.controller;

import org.springframework.http.HttpStatus;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;
import ru.netology.sqlHib.entity.City;
import ru.netology.sqlHib.entity.Person;
import ru.netology.sqlHib.service.SqlService;

import javax.annotation.security.RolesAllowed;
import java.util.List;

@RestController
public class SqlController {
    private final SqlService sqlService;

    public SqlController(SqlService sqlService) {
        this.sqlService = sqlService;
    }

    // Запрос: localhost:8080/persons/city/create?name=...
    @RolesAllowed({"ROLE_WRITE"})
    @GetMapping("${endpoint-city-create}")
    public City createCity(@RequestParam("name") String cityName) {
        try {
            return sqlService.createCity(cityName);
        } catch (Exception e) {
            throw new ResponseStatusException(HttpStatus.NOT_ACCEPTABLE, "City is already saved in the DataBase!");
        }
    }

    // Запрос: localhost:8080/persons/city/read/all
    @Secured({"ROLE_READ"})
    @GetMapping("${endpoint-city-read-all}")
    public List<City> readAllCityThanOrderByName() {
        return sqlService.readAllCityThanOrderByName();
    }

    // Запрос: localhost:8080/persons/person/read/all
    @Secured({"ROLE_READ"})
    @GetMapping("${endpoint-person-read-all}")
    public List<Person> readAllPersonThanOrderByAge() {
        return sqlService.readAllPersonThanOrderByAge();
    }

    // Запрос: localhost:8080/persons/city/read?name=...
    @Secured({"ROLE_READ"})
    @GetMapping("${endpoint-city-read}")
    public City readByName(@RequestParam("name") String cityName) {
        try {
            return sqlService.readCityByName(cityName);
        } catch (Exception e) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "City not found in the DataBase!");
        }
    }
}
