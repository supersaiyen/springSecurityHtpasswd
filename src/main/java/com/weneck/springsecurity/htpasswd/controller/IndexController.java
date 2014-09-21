package com.weneck.springsecurity.htpasswd.controller;

import java.util.logging.Logger;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.ModelAndView;


@Controller
@RequestMapping("/**")
public class IndexController {
		
	@RequestMapping(value = "*")
	public ModelAndView catchAll(){
		ModelAndView mav = new ModelAndView();
		Logger log = Logger.getLogger(IndexController.class.getName());
		log.info("We have reached the catchAll...");

		mav.addObject("status", "success");
		return mav;
	}
}