package com.cardinalsolutions.childrens.controller;

import junit.framework.Assert;

import org.junit.Test;
import org.mockito.InjectMocks;
import org.springframework.web.servlet.ModelAndView;

import com.cardinalsolutions.childrens.BaseTest;
import com.weneck.springsecurity.htpasswd.controller.IndexController;

/**
 * Tests the functionality of the Index Controller
 * @author rweneck
 *
 */
public class IndexControllerTest extends BaseTest {

	@InjectMocks
	private IndexController indexController;

	@Test
	public void testCatchAll(){
		ModelAndView mav = indexController.catchAll();
		Assert.assertNotNull(mav);
	}
	
}
