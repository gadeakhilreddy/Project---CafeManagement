package com.inn.cafe.wrapper;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class UserWrapper {


    private Integer id;

    private  String name;

    private String contactNumber;

    private String email;

    private String status;

//    public UserWrapper(Integer id, String name, String contactNumber, String email, String status) {
//        this.id = id;
//        this.name = name;
//        this.contactNumber = contactNumber;
//        this.email = email;
//        this.status = status;
//    }
//


}
