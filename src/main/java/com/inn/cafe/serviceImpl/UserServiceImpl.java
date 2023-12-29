package com.inn.cafe.serviceImpl;

import com.google.common.base.Strings;
import com.inn.cafe.JWT.CustomerUsersDetailsService;
import com.inn.cafe.JWT.JWTUtil;
import com.inn.cafe.JWT.JwtFilter;
import com.inn.cafe.POJO.User;
import com.inn.cafe.constants.CafeConstants;
import com.inn.cafe.dao.UserDao;
import com.inn.cafe.service.UserService;
import com.inn.cafe.utils.CafeUtils;
import com.inn.cafe.utils.EmailUtils;
import com.inn.cafe.wrapper.UserWrapper;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

import java.util.*;

@Slf4j
@Service
public class UserServiceImpl implements UserService {

    @Autowired
    UserDao userDao;

    @Autowired
    CustomerUsersDetailsService customerUsersDetailsService;

    @Autowired
    AuthenticationManager authenticationManager;

    @Autowired
    JWTUtil jwtUtil;

    @Autowired
    JwtFilter jwtFilter;

    @Autowired
    EmailUtils emailUtils;

    @Override
    public ResponseEntity<String> signUp(Map<String, String> requestMap) {

        log.info("Inside the signup() : " + requestMap);
        try {
            if (validateSignupMap(requestMap)) {
                User user = userDao.findByEmailId(requestMap.get("email"));
                if (Objects.isNull(user)) {
                    userDao.save(getUserFromMap(requestMap));
                    return CafeUtils.getResponseEntity("Successfully Registered.", HttpStatus.OK);
                } else {
                    return CafeUtils.getResponseEntity("Email already exists", HttpStatus.BAD_REQUEST);
                }
            } else {
                 return CafeUtils.getResponseEntity(CafeConstants.INVALID_DATA, HttpStatus.BAD_REQUEST);
            }
        }catch (Exception ex){
            ex.printStackTrace();
        }
        return CafeUtils.getResponseEntity(CafeConstants.SOMETHING_WENT_WRONG,HttpStatus.INTERNAL_SERVER_ERROR);
    }



    private boolean validateSignupMap(Map<String,String> requestMap){
        if(requestMap.containsKey("name")&& requestMap.containsKey("email")&& requestMap.containsKey("contactNumber")
        && requestMap.containsKey("password")){
            return true;
        }
        return false;
    }

    private User getUserFromMap(Map<String,String> requestMap){
        User user=new User();
        user.setName(requestMap.get("name"));
        user.setEmail(requestMap.get("email"));
        user.setContactNumber(requestMap.get("contactNumber"));
        user.setPassword(requestMap.get("password"));
        user.setStatus("false");
        user.setRole("user");
        return user;
    }

    @Override
    public ResponseEntity<String> login(Map<String, String> requestMap) {
        log.info("Inside the login() : " + requestMap);
        try{
            Authentication auth = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(requestMap.get("email"),requestMap.get("password"))
            );

            if(auth.isAuthenticated()){
                if(customerUsersDetailsService.getUserDetail().getStatus().equalsIgnoreCase("true")){
                    return new ResponseEntity<String>("{\"token\":\"" + jwtUtil.generateToken(customerUsersDetailsService.getUserDetail().getEmail()
                            ,customerUsersDetailsService.getUserDetail().getRole()) + "\"}",HttpStatus.OK);
                }else{
                    return new ResponseEntity<String>("{\"message\" : \"" + "Wait for Admin Approval" +"\"}",HttpStatus.BAD_REQUEST);
                }
            }

        }catch (Exception ex){
            log.error("{}",ex);
        }
        return new ResponseEntity<String>("{\"message\" : \"" + "Bad Credentials" +"\"}",HttpStatus.BAD_REQUEST);
    }

    @Override
    public ResponseEntity<List<UserWrapper>> getAllUsers() {
        try{
            if(jwtFilter.isAdmin()){
                return new ResponseEntity<>(userDao.getAllUsers(), HttpStatus.OK);
            }else {
                return new ResponseEntity<>(new ArrayList<>(),HttpStatus.UNAUTHORIZED);
                //return new ResponseEntity<List<UserWrapper>>(userDao.getAllUsers(), HttpStatus.OK);
            }

        }catch (Exception ex){
            ex.printStackTrace();
        }
        return new ResponseEntity<>(new ArrayList<>(),HttpStatus.INTERNAL_SERVER_ERROR);
    }

    @Override
    public ResponseEntity<String> update(Map<String, String> requestMap) {
        try{
            if(jwtFilter.isAdmin()){
                Optional<User> optional=userDao.findById(Integer.parseInt(requestMap.get("id")));
                if(!optional.isEmpty()){
                    userDao.updateStatus(requestMap.get("status"),Integer.parseInt(requestMap.get("id")));
                    sendMailToAllAdmin(requestMap.get("status"),optional.get().getEmail(),userDao.getAllAdmins());
                    return CafeUtils.getResponseEntity("User status data updated",HttpStatus.OK);
                }else{
                    return CafeUtils.getResponseEntity("User doesn't exist",HttpStatus.OK);
                }

            }else{
                return CafeUtils.getResponseEntity(CafeConstants.UNAUTHORIZED_ACCESS,HttpStatus.UNAUTHORIZED);
            }

        }catch(Exception ex){
            ex.printStackTrace();
        }
        return CafeUtils.getResponseEntity(CafeConstants.UNAUTHORIZED_ACCESS,HttpStatus.UNAUTHORIZED);
    }

    @Override
    public ResponseEntity<String> checkToken() {
        return CafeUtils.getResponseEntity("true",HttpStatus.OK);
    }

    @Override
    public ResponseEntity<String> changePassword(Map<String, String> requestMap) {
        try{
            User currentUser = userDao.findByEmail(jwtFilter.getCurrentUser());
            if(!currentUser.equals(null)){
                if(currentUser.getPassword().equalsIgnoreCase(requestMap.get("oldPassword"))){
                    currentUser.setPassword(requestMap.get("newPassword"));
                    userDao.save(currentUser);
                    return CafeUtils.getResponseEntity("Password Changed Successfully",HttpStatus.OK);
                }
                return CafeUtils.getResponseEntity("Incorrect Old Password",HttpStatus.BAD_REQUEST);
            }
            return CafeUtils.getResponseEntity(CafeConstants.SOMETHING_WENT_WRONG,HttpStatus.INTERNAL_SERVER_ERROR);
        }catch (Exception ex){
            ex.printStackTrace();
        }
        return CafeUtils.getResponseEntity(CafeConstants.SOMETHING_WENT_WRONG,HttpStatus.INTERNAL_SERVER_ERROR);
    }

    @Override
    public ResponseEntity<String> forgotPassword(Map<String, String> requestMap) {
        try{
            User currentUser = userDao.findByEmail(requestMap.get("email"));
            if(!Objects.isNull(currentUser) && !Strings.isNullOrEmpty(currentUser.getEmail())){
                emailUtils.forgotPassword(currentUser.getEmail(),"Credentials sent by Management Team", currentUser.getPassword());
            }
            return CafeUtils.getResponseEntity("Credentials sent to your registered email.",HttpStatus.OK);

        }catch (Exception ex){
            ex.printStackTrace();
        }
        return CafeUtils.getResponseEntity(CafeConstants.SOMETHING_WENT_WRONG,HttpStatus.INTERNAL_SERVER_ERROR);
    }

    private void sendMailToAllAdmin(String status, String user, List<String> allAdmins) {
        allAdmins.remove(jwtFilter.getCurrentUser());
        if(status!=null && status.equalsIgnoreCase("true")){
            emailUtils.sendMessage(jwtFilter.getCurrentUser(),"Account approved","USER:- "+ user + "\n is approved by \n ADMIN:- " + jwtFilter.getCurrentUser(),allAdmins);
        }else{
            emailUtils.sendMessage(jwtFilter.getCurrentUser(),"Account disabled","USER:- "+ user + "\n is disabled by \n ADMIN:- " + jwtFilter.getCurrentUser(),allAdmins);
        }
    }
}
